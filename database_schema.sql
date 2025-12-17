-- Database Schema for Forensic Artifacts
-- SQLite schema for storing parsed forensic data

-- Cases table
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT UNIQUE NOT NULL,
    image_path TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'processing'
);

-- Prefetch files (program execution history)
CREATE TABLE IF NOT EXISTS prefetch (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    executable_name TEXT,
    run_time TEXT,
    prefetch_hash TEXT,
    file_path TEXT,
    files_loaded TEXT,
    volume_info TEXT,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

-- Event logs (Windows events)
CREATE TABLE IF NOT EXISTS eventlog (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    event_id INTEGER,
    timestamp TEXT,
    source TEXT,
    level TEXT,
    computer_name TEXT,
    user_name TEXT,
    message TEXT,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

-- Registry entries
CREATE TABLE IF NOT EXISTS registry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    hive_type TEXT,
    key_path TEXT,
    value_name TEXT,
    value_data TEXT,
    value_type TEXT,
    last_modified TEXT,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

-- Browser history
CREATE TABLE IF NOT EXISTS browser_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    browser TEXT,
    url TEXT,
    title TEXT,
    visit_time TEXT,
    visit_count INTEGER DEFAULT 0,
    typed_count INTEGER DEFAULT 0,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

-- LNK (shortcut) files
CREATE TABLE IF NOT EXISTS lnk_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    lnk_name TEXT,
    target_path TEXT,
    working_directory TEXT,
    arguments TEXT,
    creation_time TEXT,
    access_time TEXT,
    modified_time TEXT,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

-- Create indexes for faster queries
CREATE INDEX IF NOT EXISTS idx_prefetch_case ON prefetch(case_id);
CREATE INDEX IF NOT EXISTS idx_prefetch_executable ON prefetch(executable_name);
CREATE INDEX IF NOT EXISTS idx_eventlog_case ON eventlog(case_id);
CREATE INDEX IF NOT EXISTS idx_eventlog_event_id ON eventlog(event_id);
CREATE INDEX IF NOT EXISTS idx_eventlog_timestamp ON eventlog(timestamp);
CREATE INDEX IF NOT EXISTS idx_registry_case ON registry(case_id);
CREATE INDEX IF NOT EXISTS idx_browser_case ON browser_history(case_id);
CREATE INDEX IF NOT EXISTS idx_lnk_case ON lnk_files(case_id);
