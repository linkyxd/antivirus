ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(255) UNIQUE;

CREATE TABLE IF NOT EXISTS product (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    is_blocked BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS license_type (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(64) NOT NULL,
    default_duration_in_days INT NOT NULL,
    description TEXT
);

CREATE TABLE IF NOT EXISTS license (
    id BIGSERIAL PRIMARY KEY,
    code VARCHAR(255) NOT NULL UNIQUE,
    product_id BIGINT NOT NULL REFERENCES product(id),
    type_id BIGINT NOT NULL REFERENCES license_type(id),
    owner_id BIGINT NOT NULL REFERENCES users(id),
    user_id BIGINT REFERENCES users(id),
    first_activation_date TIMESTAMP,
    ending_date TIMESTAMP,
    blocked BOOLEAN NOT NULL DEFAULT FALSE,
    device_count INT NOT NULL DEFAULT 1,
    description TEXT
);

CREATE TABLE IF NOT EXISTS device (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255),
    mac_address VARCHAR(64) NOT NULL UNIQUE,
    user_id BIGINT NOT NULL REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS device_license (
    id BIGSERIAL PRIMARY KEY,
    license_id BIGINT NOT NULL REFERENCES license(id),
    device_id BIGINT NOT NULL REFERENCES device(id),
    activation_date TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS license_history (
    id BIGSERIAL PRIMARY KEY,
    license_id BIGINT NOT NULL REFERENCES license(id),
    user_id BIGINT NOT NULL REFERENCES users(id),
    status VARCHAR(64) NOT NULL,
    change_date TIMESTAMP NOT NULL DEFAULT NOW(),
    description TEXT
);

CREATE INDEX IF NOT EXISTS idx_license_code ON license(code);
CREATE INDEX IF NOT EXISTS idx_device_mac ON device(mac_address);
CREATE INDEX IF NOT EXISTS idx_device_license_license ON device_license(license_id);
CREATE INDEX IF NOT EXISTS idx_device_license_device ON device_license(device_id);
CREATE INDEX IF NOT EXISTS idx_license_history_license ON license_history(license_id);
