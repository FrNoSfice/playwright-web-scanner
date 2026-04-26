CREATE DATABASE IF NOT EXISTS webscan
DEFAULT CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

USE webscan;

CREATE TABLE IF NOT EXISTS task_info (
    id INT PRIMARY KEY AUTO_INCREMENT,
    task_name VARCHAR(255) NOT NULL,
    target_url TEXT NOT NULL,
    scan_depth INT DEFAULT 1,
    remark TEXT,
    scan_status TINYINT DEFAULT 0 COMMENT '0未开始 1扫描中 2已完成 3失败',
    total_pages INT DEFAULT 0,
    total_vulns INT DEFAULT 0,
    high_risk_count INT DEFAULT 0,
    medium_risk_count INT DEFAULT 0,
    low_risk_count INT DEFAULT 0,
    success_pages INT DEFAULT 0,
    failed_pages INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    started_at DATETIME NULL,
    finished_at DATETIME NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS page_info (
    id INT PRIMARY KEY AUTO_INCREMENT,
    task_id INT NOT NULL,
    page_url TEXT NOT NULL,
    page_title VARCHAR(255),
    request_method VARCHAR(20) DEFAULT 'GET',
    response_status INT,
    page_level INT DEFAULT 1,
    link_count INT DEFAULT 0,
    form_count INT DEFAULT 0,
    input_count INT DEFAULT 0,
    textarea_count INT DEFAULT 0,
    button_count INT DEFAULT 0,
    is_scanned TINYINT DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_task_id (task_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS vuln_result (
    id INT PRIMARY KEY AUTO_INCREMENT,
    task_id INT NOT NULL,
    page_id INT,
    vuln_name VARCHAR(255) NOT NULL,
    vuln_type VARCHAR(100),
    risk_level TINYINT DEFAULT 1 COMMENT '1低危 2中危 3高危',
    page_url TEXT,
    param_name TEXT,
    param_position VARCHAR(100),
    payload TEXT,
    vuln_desc TEXT,
    evidence TEXT,
    suggestion TEXT,
    scan_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_task_id (task_id),
    INDEX idx_page_id (page_id),
    INDEX idx_risk_level (risk_level)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS scan_log (
    id INT PRIMARY KEY AUTO_INCREMENT,
    task_id INT NOT NULL,
    log_level VARCHAR(20) DEFAULT 'INFO',
    log_content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_task_id (task_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;