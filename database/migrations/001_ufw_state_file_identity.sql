ALTER TABLE ufw_state
    MODIFY COLUMN id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    ADD COLUMN file_device BIGINT UNSIGNED NULL,
    ADD COLUMN file_inode BIGINT UNSIGNED NULL,
    ADD UNIQUE KEY uq_ufw_state_file (file_device, file_inode);
