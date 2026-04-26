CREATE DATABASE IF NOT EXISTS test_lab
DEFAULT CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

USE test_lab;

CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50),
    password VARCHAR(100),
    email VARCHAR(100)
);

INSERT INTO users (username, password, email) VALUES
('admin', 'admin123', 'admin@test.local'),
('test', 'test123', 'test@test.local');

CREATE TABLE IF NOT EXISTS messages (
    id INT PRIMARY KEY AUTO_INCREMENT,
    content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);