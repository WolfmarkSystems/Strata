import React, { useState, useEffect } from 'react';
import './index.css';

function App() {
  const [stats, setStats] = useState({ parsed: 0, hashes: 0, flags: 0 });

  useEffect(() => {
    // Simulate real-time forensic socket parsing metrics
    const interval = setInterval(() => {
      setStats(prev => ({
        parsed: prev.parsed + Math.floor(Math.random() * 50),
        hashes: prev.hashes + Math.floor(Math.random() * 20),
        flags: prev.flags + (Math.random() > 0.8 ? 1 : 0)
      }));
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="dashboard-container">
      <header>
        <h1>Vantor Shield Intelligence</h1>
        <p style={{ color: 'var(--text-secondary)' }}>Live Advanced Telemetry & Reporting Dashboard</p>
      </header>

      <div className="grid">
        <div className="card">
          <h2>Files Parsed (Rayon Multi-thread)</h2>
          <div className="stat">{stats.parsed.toLocaleString()}</div>
        </div>
        <div className="card">
          <h2>MD5/SHA256 Hashes Computed</h2>
          <div className="stat">{stats.hashes.toLocaleString()}</div>
        </div>
        <div className="card">
          <h2>YARA Threats / IOC Flags</h2>
          <div className="stat" style={{ color: stats.flags > 0 ? '#ef4444' : '#fff' }}>
            {stats.flags.toLocaleString()}
          </div>
        </div>
      </div>

      <div className="timeline">
        <h2 style={{ marginBottom: '1.5rem', color: '#fff' }}>Super-Timeline Live Extraction Engine</h2>
        
        <div className="timeline-event">
          <div className="time">2026-03-21 15:43:02</div>
          <div>Project VIC Hash Match: CSAM_Tier1 [1a79a4d60de6...]</div>
        </div>
        
        <div className="timeline-event" style={{ borderLeftColor: '#8b5cf6' }}>
          <div className="time">2026-03-21 15:42:10</div>
          <div>TikTok drafts.sqlite decrypted. Recovered 4 cached artifacts.</div>
        </div>
        
        <div className="timeline-event" style={{ borderLeftColor: '#10b981' }}>
          <div className="time">2026-03-21 15:39:15</div>
          <div>ZNotes.sqlite Apple Protobuf decompression complete. Parsed 12 notes.</div>
        </div>

        <div className="timeline-event" style={{ borderLeftColor: '#f59e0b' }}>
          <div className="time">2026-03-21 15:30:00</div>
          <div>iCloud Manifest.db raw bypass executed successfully.</div>
        </div>
      </div>
    </div>
  );
}

export default App;
