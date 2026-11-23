-- Database schema for the password vault.
-- Encoding utf8mb4. Import on the hosting (phpMyAdmin -> Import)
-- or from the command line:
--   mysql -u <user> -p <database> < schema.sql
--
-- IMPORTANT: the server stores ONLY encrypted data.
-- Service names and passwords are encrypted in the browser (WebCrypto, AES-256-GCM)
-- and reach the server only as ciphertext + salt + IV.

CREATE TABLE IF NOT EXISTS users (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    username VARCHAR(64) NOT NULL COMMENT 'Username (may be an e-mail)',
    password_hash VARCHAR(255) NOT NULL COMMENT 'Site password hash (Argon2id or bcrypt)',
    kdf_salt VARCHAR(64) NOT NULL COMMENT 'PBKDF2 salt for the encryption key (base64). Not secret.',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS vault_entries (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id INT UNSIGNED NOT NULL,
    salt VARCHAR(64) NOT NULL COMMENT 'Salt (AAD) for the entry (base64)',
    iv VARCHAR(64) NOT NULL COMMENT 'IV for AES-GCM (base64)',
    data MEDIUMTEXT NOT NULL COMMENT 'Encrypted JSON {service, login, password, note} + AES-GCM tag (base64)',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_vault_user (user_id),
    CONSTRAINT fk_vault_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS login_attempts (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    ip VARCHAR(45) NOT NULL,
    username VARCHAR(64) NOT NULL,
    attempted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_attempts_ip_time (ip, attempted_at),
    KEY idx_attempts_user_time (username, attempted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
