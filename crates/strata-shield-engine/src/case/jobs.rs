use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub case_id: String,
    pub job_type: JobType,
    pub status: JobStatus,
    pub priority: JobPriority,
    pub created_at: u64,
    pub started_at: Option<u64>,
    pub completed_at: Option<u64>,
    pub progress: f32,
    pub progress_message: String,
    pub result: Option<JobResult>,
    pub error: Option<String>,
    pub params: JobParams,
    pub created_by: String,
    pub worker_id: Option<String>,
    pub retries: u32,
    pub max_retries: u32,
}

impl Job {
    pub fn new(case_id: &str, job_type: JobType, params: JobParams, created_by: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            case_id: case_id.to_string(),
            job_type,
            status: JobStatus::Pending,
            priority: JobPriority::Normal,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            started_at: None,
            completed_at: None,
            progress: 0.0,
            progress_message: "Created".to_string(),
            result: None,
            error: None,
            params,
            created_by: created_by.to_string(),
            worker_id: None,
            retries: 0,
            max_retries: 3,
        }
    }

    pub fn start(&mut self, worker_id: &str) {
        self.status = JobStatus::Running;
        self.started_at = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        self.worker_id = Some(worker_id.to_string());
    }

    pub fn update_progress(&mut self, progress: f32, message: &str) {
        self.progress = progress.clamp(0.0, 100.0);
        self.progress_message = message.to_string();
    }

    pub fn complete(&mut self, result: JobResult) {
        self.status = JobStatus::Completed;
        self.completed_at = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        self.progress = 100.0;
        self.result = Some(result);
    }

    pub fn fail(&mut self, error: &str) {
        self.retries += 1;
        if self.retries >= self.max_retries {
            self.status = JobStatus::Failed;
            self.error = Some(error.to_string());
            self.completed_at = Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            );
        } else {
            self.status = JobStatus::Pending;
            self.error = Some(error.to_string());
        }
    }

    pub fn cancel(&mut self) {
        self.status = JobStatus::Cancelled;
        self.completed_at = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
    }

    pub fn pause(&mut self) {
        if self.status == JobStatus::Running {
            self.status = JobStatus::Paused;
        }
    }

    pub fn resume(&mut self) {
        if self.status == JobStatus::Paused {
            self.status = JobStatus::Running;
        }
    }

    pub fn duration_ms(&self) -> Option<u64> {
        match (self.started_at, self.completed_at) {
            (Some(start), Some(end)) => Some(end - start),
            (Some(start), None) => Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    - start,
            ),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum JobType {
    ImageAcquisition,
    Carving,
    HashComputation,
    Indexing,
    ArtifactExtraction,
    TimelineGeneration,
    ReportGeneration,
    Export,
    Verification,
    Deduplication,
    EnCaseImport,
    FTKImport,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum JobStatus {
    Pending,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum JobPriority {
    Low,
    Normal,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JobParams {
    pub evidence_id: Option<String>,
    pub volume_id: Option<String>,
    pub output_path: Option<String>,
    pub filters: Option<HashMap<String, String>>,
    pub options: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JobResult {
    Success,
    PartialFailure { error_count: usize },
    NoResults,
    Custom { data: HashMap<String, String> },
}

pub struct JobWorker {
    pub id: String,
    pub name: String,
    pub status: WorkerStatus,
    pub current_job_id: Option<String>,
    pub jobs_completed: u64,
    pub jobs_failed: u64,
    pub started_at: u64,
    pub last_heartbeat: u64,
}

impl JobWorker {
    pub fn new(id: &str, name: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            status: WorkerStatus::Idle,
            current_job_id: None,
            jobs_completed: 0,
            jobs_failed: 0,
            started_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            last_heartbeat: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    pub fn heartbeat(&mut self) {
        self.last_heartbeat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    pub fn assign_job(&mut self, job_id: &str) {
        self.current_job_id = Some(job_id.to_string());
        self.status = WorkerStatus::Busy;
    }

    pub fn release_job(&mut self, success: bool) {
        if success {
            self.jobs_completed += 1;
        } else {
            self.jobs_failed += 1;
        }
        self.current_job_id = None;
        self.status = WorkerStatus::Idle;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WorkerStatus {
    Idle,
    Busy,
    Paused,
    Offline,
}

pub struct JobQueue {
    _case_id: String,
    jobs: HashMap<String, Job>,
    pending_queue: Vec<String>,
    running_jobs: Vec<String>,
    completed_jobs: Vec<String>,
    failed_jobs: Vec<String>,
    workers: HashMap<String, JobWorker>,
}

impl JobQueue {
    pub fn new(case_id: &str) -> Self {
        Self {
            _case_id: case_id.to_string(),
            jobs: HashMap::new(),
            pending_queue: Vec::new(),
            running_jobs: Vec::new(),
            completed_jobs: Vec::new(),
            failed_jobs: Vec::new(),
            workers: HashMap::new(),
        }
    }

    pub fn submit(&mut self, job: Job) -> String {
        let id = job.id.clone();
        let priority = job.priority.clone();

        self.jobs.insert(id.clone(), job);

        let insert_pos = self
            .pending_queue
            .iter()
            .position(|jid| {
                self.jobs
                    .get(jid)
                    .map(|j| j.priority < priority)
                    .unwrap_or(false)
            })
            .unwrap_or(self.pending_queue.len());

        self.pending_queue.insert(insert_pos, id.clone());
        id
    }

    pub fn get_job(&self, id: &str) -> Option<&Job> {
        self.jobs.get(id)
    }

    pub fn get_job_mut(&mut self, id: &str) -> Option<&mut Job> {
        self.jobs.get_mut(id)
    }

    pub fn get_next_job(&mut self, worker_id: &str) -> Option<String> {
        if let Some(job_id) = self.pending_queue.pop() {
            if let Some(job) = self.jobs.get_mut(&job_id) {
                job.start(worker_id);
                self.running_jobs.push(job_id.clone());
                return Some(job_id);
            }
        }
        None
    }

    pub fn complete_job(&mut self, job_id: &str, result: JobResult) -> bool {
        if let Some(job) = self.jobs.get_mut(job_id) {
            job.complete(result);
            self.running_jobs.retain(|id| id != job_id);
            self.completed_jobs.push(job_id.to_string());
            return true;
        }
        false
    }

    pub fn fail_job(&mut self, job_id: &str, error: &str) -> bool {
        if let Some(job) = self.jobs.get_mut(job_id) {
            job.fail(error);
            self.running_jobs.retain(|id| id != job_id);
            if job.status == JobStatus::Failed {
                self.failed_jobs.push(job_id.to_string());
            }
            return true;
        }
        false
    }

    pub fn cancel_job(&mut self, job_id: &str) -> bool {
        if let Some(job) = self.jobs.get_mut(job_id) {
            job.cancel();
            self.pending_queue.retain(|id| id != job_id);
            self.running_jobs.retain(|id| id != job_id);
            return true;
        }
        false
    }

    pub fn register_worker(&mut self, worker: JobWorker) {
        self.workers.insert(worker.id.clone(), worker);
    }

    pub fn unregister_worker(&mut self, worker_id: &str) -> bool {
        if let Some(worker) = self.workers.get_mut(worker_id) {
            worker.status = WorkerStatus::Offline;
            return self.workers.remove(worker_id).is_some();
        }
        false
    }

    pub fn get_worker(&self, worker_id: &str) -> Option<&JobWorker> {
        self.workers.get(worker_id)
    }

    pub fn list_workers(&self) -> Vec<&JobWorker> {
        self.workers.values().collect()
    }

    pub fn list_pending_jobs(&self) -> Vec<&Job> {
        self.pending_queue
            .iter()
            .filter_map(|id| self.jobs.get(id))
            .collect()
    }

    pub fn list_running_jobs(&self) -> Vec<&Job> {
        self.running_jobs
            .iter()
            .filter_map(|id| self.jobs.get(id))
            .collect()
    }

    pub fn list_completed_jobs(&self) -> Vec<&Job> {
        self.completed_jobs
            .iter()
            .filter_map(|id| self.jobs.get(id))
            .collect()
    }

    pub fn list_failed_jobs(&self) -> Vec<&Job> {
        self.failed_jobs
            .iter()
            .filter_map(|id| self.jobs.get(id))
            .collect()
    }

    pub fn get_jobs_by_status(&self, status: JobStatus) -> Vec<&Job> {
        self.jobs.values().filter(|j| j.status == status).collect()
    }

    pub fn get_jobs_by_type(&self, job_type: JobType) -> Vec<&Job> {
        self.jobs
            .values()
            .filter(|j| j.job_type == job_type)
            .collect()
    }

    pub fn get_queue_stats(&self) -> JobQueueStats {
        JobQueueStats {
            pending: self.pending_queue.len(),
            running: self.running_jobs.len(),
            completed: self.completed_jobs.len(),
            failed: self.failed_jobs.len(),
            workers_online: self
                .workers
                .values()
                .filter(|w| w.status != WorkerStatus::Offline)
                .count(),
            workers_busy: self
                .workers
                .values()
                .filter(|w| w.status == WorkerStatus::Busy)
                .count(),
        }
    }

    pub fn cleanup_completed(&mut self, keep_last: usize) {
        while self.completed_jobs.len() > keep_last {
            if let Some(id) = self.completed_jobs.first() {
                self.jobs.remove(id);
                self.completed_jobs.remove(0);
            }
        }
    }

    pub fn retry_failed(&mut self) {
        for id in &self.failed_jobs {
            if let Some(job) = self.jobs.get_mut(id) {
                job.status = JobStatus::Pending;
                job.error = None;
                self.pending_queue.push(id.clone());
            }
        }
        self.failed_jobs.clear();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobQueueStats {
    pub pending: usize,
    pub running: usize,
    pub completed: usize,
    pub failed: usize,
    pub workers_online: usize,
    pub workers_busy: usize,
}

pub struct JobManager {
    queues: HashMap<String, JobQueue>,
}

impl JobManager {
    pub fn new() -> Self {
        Self {
            queues: HashMap::new(),
        }
    }

    pub fn create_queue(&mut self, case_id: &str) {
        if !self.queues.contains_key(case_id) {
            self.queues
                .insert(case_id.to_string(), JobQueue::new(case_id));
        }
    }

    pub fn get_queue(&self, case_id: &str) -> Option<&JobQueue> {
        self.queues.get(case_id)
    }

    pub fn get_queue_mut(&mut self, case_id: &str) -> Option<&mut JobQueue> {
        self.queues.get_mut(case_id)
    }

    pub fn list_case_ids(&self) -> Vec<&String> {
        self.queues.keys().collect()
    }

    pub fn get_all_stats(&self) -> HashMap<String, JobQueueStats> {
        self.queues
            .iter()
            .map(|(id, queue)| (id.clone(), queue.get_queue_stats()))
            .collect()
    }
}

impl Default for JobManager {
    fn default() -> Self {
        Self::new()
    }
}
