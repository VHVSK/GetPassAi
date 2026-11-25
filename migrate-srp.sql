-- Migration to SRP authentication (phase 3) — for getpassai.com ONLY.
--
-- Run this ONLY after deleting every account on getpassai.com
-- (it has no real users yet — only the test account).
-- The old password_hash values are useless under SRP: every user
-- must re-register, and the browser computes a fresh verifier.
--
-- NEVER run this on passai.vyhivskyi.com: it has real accounts,
-- and dropping password_hash would lock them out. Its migration
-- is a separate decision (it needs a migration flow, not a drop).
--
-- Apply in phpMyAdmin -> SQL, or from the command line:
--   mysql -u <user> -p <database> < migrate-srp.sql

ALTER TABLE users
    ADD COLUMN srp_salt VARCHAR(64) NOT NULL COMMENT 'SRP salt (hex, 16 bytes)' AFTER username,
    ADD COLUMN srp_verifier TEXT NOT NULL COMMENT 'SRP verifier v = g^x % N (hex, 2048-bit)' AFTER srp_salt,
    DROP COLUMN password_hash,
    DROP COLUMN kdf_salt;
