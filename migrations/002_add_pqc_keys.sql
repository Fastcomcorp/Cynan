-- Add PQC public key storage to users table
ALTER TABLE users ADD COLUMN ml_dsa_public_key BYTEA;
ALTER TABLE users ADD COLUMN pqc_key_created_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE users ADD COLUMN pqc_key_expires_at TIMESTAMP WITH TIME ZONE;

-- Index for key lookup
CREATE INDEX idx_users_pqc_key ON users(ml_dsa_public_key) WHERE ml_dsa_public_key IS NOT NULL;

-- PQC key metadata table
CREATE TABLE IF NOT EXISTS pqc_key_metadata (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    algorithm VARCHAR(50) NOT NULL,  -- 'ML-DSA-65', 'ML-KEM-768', etc.
    public_key BYTEA NOT NULL,
    key_usage VARCHAR(50) NOT NULL,  -- 'authentication', 'encryption', etc.
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    revoked BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_pqc_keys_user ON pqc_key_metadata(user_id);
CREATE INDEX idx_pqc_keys_algorithm ON pqc_key_metadata(algorithm);
