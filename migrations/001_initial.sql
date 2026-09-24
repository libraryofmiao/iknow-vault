CREATE TABLE IF NOT EXISTS vaults (
 id TEXT PRIMARY KEY,
 salt TEXT NOT NULL,
 iv TEXT NOT NULL,
 ciphertext TEXT NOT NULL,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vaults_updated_at ON vaults(updated_at);