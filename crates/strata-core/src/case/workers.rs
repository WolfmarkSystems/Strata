use rusqlite::{Connection, Result as SqliteResult};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

pub struct WorkerConnectionPool {
    connections: Arc<Mutex<HashMap<String, Connection>>>,
    db_path: String,
    max_connections: usize,
}

impl WorkerConnectionPool {
    pub fn new(db_path: &Path, max_connections: usize) -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            db_path: db_path.to_string_lossy().to_string(),
            max_connections,
        }
    }

    pub fn get_connection(&self, worker_id: &str) -> SqliteResult<Connection> {
        let mut pool = self.connections.lock().unwrap();

        if pool.contains_key(worker_id) {
            return Connection::open(&self.db_path);
        }

        if pool.len() >= self.max_connections {
            let evicted = pool.keys().next().cloned();
            if let Some(key) = evicted {
                pool.remove(&key);
            }
        }

        let conn = Connection::open(&self.db_path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA temp_store=MEMORY;
             PRAGMA foreign_keys=ON;
             PRAGMA mmap_size=268435456;
             PRAGMA cache_size=-65536;
             PRAGMA busy_timeout=5000;",
        )?;

        pool.insert(worker_id.to_string(), conn);

        Connection::open(&self.db_path)
    }

    pub fn release_connection(&self, worker_id: &str) {
        let mut pool = self.connections.lock().unwrap();
        pool.remove(worker_id);
    }

    pub fn close_all(&self) {
        let mut pool = self.connections.lock().unwrap();
        pool.clear();
    }

    pub fn connection_count(&self) -> usize {
        let pool = self.connections.lock().unwrap();
        pool.len()
    }
}

pub struct WorkerConnection {
    _pool: WorkerConnectionPool,
    _worker_id: String,
    conn: Option<Connection>,
}

impl WorkerConnection {
    pub fn new(pool: WorkerConnectionPool, worker_id: &str) -> SqliteResult<Self> {
        let conn = pool.get_connection(worker_id)?;
        Ok(Self {
            _pool: pool,
            _worker_id: worker_id.to_string(),
            conn: Some(conn),
        })
    }

    pub fn connection(&self) -> Option<&Connection> {
        self.conn.as_ref()
    }

    pub fn connection_mut(&mut self) -> Option<&mut Connection> {
        self.conn.as_mut()
    }
}

impl Drop for WorkerConnection {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            let _ = conn.close();
        }
    }
}

pub struct BatchWriter {
    _pool: WorkerConnectionPool,
    batch_size: usize,
    pending_writes: usize,
}

impl BatchWriter {
    pub fn new(pool: WorkerConnectionPool, batch_size: usize) -> Self {
        Self {
            _pool: pool,
            batch_size,
            pending_writes: 0,
        }
    }

    pub fn should_flush(&self) -> bool {
        self.pending_writes >= self.batch_size
    }

    pub fn record_write(&mut self) {
        self.pending_writes += 1;
    }

    pub fn flush(&mut self) {
        self.pending_writes = 0;
    }

    pub fn batch_size(&self) -> usize {
        self.batch_size
    }
}

pub fn create_worker_connection(db_path: &Path, _worker_id: &str) -> SqliteResult<Connection> {
    let conn = Connection::open(db_path)?;

    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA temp_store=MEMORY;
         PRAGMA foreign_keys=ON;
         PRAGMA mmap_size=268435456;
         PRAGMA cache_size=-65536;
         PRAGMA busy_timeout=5000;",
    )?;

    Ok(conn)
}

pub struct RetryConfig {
    pub max_retries: u32,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay_ms: 100,
            max_delay_ms: 5000,
            backoff_multiplier: 2.0,
        }
    }
}

impl RetryConfig {
    pub fn calculate_delay(&self, attempt: u32) -> u64 {
        let delay = self.initial_delay_ms * (self.backoff_multiplier.powi(attempt as i32) as u64);
        delay.min(self.max_delay_ms)
    }
}

pub fn execute_with_retry<T, F>(
    config: &RetryConfig,
    mut operation: F,
) -> Result<T, rusqlite::Error>
where
    F: FnMut() -> Result<T, rusqlite::Error>,
{
    let mut attempt = 0;

    loop {
        match operation() {
            Ok(result) => return Ok(result),
            Err(e) if attempt >= config.max_retries => return Err(e),
            Err(_) => {
                let delay = config.calculate_delay(attempt);
                std::thread::sleep(std::time::Duration::from_millis(delay));
                attempt += 1;
            }
        }
    }
}
