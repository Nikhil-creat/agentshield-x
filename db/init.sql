-- AgentShield-X audit schema: append-only, tamper-evident, row-level-security protected.
-- Applied by db/init.sh as the owner role. Roles are created there (passwords come from the environment).

CREATE TABLE IF NOT EXISTS audit_log (
    ledger_id       text        NOT NULL,           -- one Merkle ledger per API replica
    seq             bigint      NOT NULL,
    ts              timestamptz NOT NULL,
    kind            text        NOT NULL,
    actor           text        NOT NULL,           -- pseudonymous subject, never raw PII
    payload_digest  char(64)    NOT NULL,           -- SHA-256 / HMAC of the payload (payload itself is never stored)
    meta            jsonb       NOT NULL DEFAULT '{}'::jsonb,
    prev            char(64)    NOT NULL,           -- hash chain
    leaf            char(64)    NOT NULL,           -- Merkle leaf hash
    PRIMARY KEY (ledger_id, seq)
);
CREATE INDEX IF NOT EXISTS audit_log_ts_idx    ON audit_log (ts);
CREATE INDEX IF NOT EXISTS audit_log_kind_idx  ON audit_log (kind, ts);
CREATE INDEX IF NOT EXISTS audit_log_actor_idx ON audit_log (actor, ts);

CREATE TABLE IF NOT EXISTS audit_checkpoints (
    ledger_id  text        NOT NULL,
    size       bigint      NOT NULL,
    root       char(64)    NOT NULL,
    ts         timestamptz NOT NULL,
    signature  text        NOT NULL,                -- Ed25519 over canonical {size, root, ts}
    PRIMARY KEY (ledger_id, size)
);

-- ---- immutability: no UPDATE / DELETE / TRUNCATE for anyone, including the owner's application roles ----
CREATE OR REPLACE FUNCTION audit_forbid_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit tables are append-only (% on %)', TG_OP, TG_TABLE_NAME USING ERRCODE = '42501';
END $$;

DROP TRIGGER IF EXISTS audit_log_no_mutation ON audit_log;
CREATE TRIGGER audit_log_no_mutation BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_forbid_mutation();
DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log;
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_forbid_mutation();
DROP TRIGGER IF EXISTS audit_ckpt_no_mutation ON audit_checkpoints;
CREATE TRIGGER audit_ckpt_no_mutation BEFORE UPDATE OR DELETE ON audit_checkpoints
    FOR EACH ROW EXECUTE FUNCTION audit_forbid_mutation();

-- ---- row-level security: writers may only INSERT, auditors may only SELECT ----
ALTER TABLE audit_log         ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log         FORCE  ROW LEVEL SECURITY;   -- applies to the table owner too
ALTER TABLE audit_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_checkpoints FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS audit_insert ON audit_log;
CREATE POLICY audit_insert ON audit_log FOR INSERT TO shield_writer WITH CHECK (true);
DROP POLICY IF EXISTS audit_read ON audit_log;
CREATE POLICY audit_read ON audit_log FOR SELECT TO shield_auditor USING (true);
DROP POLICY IF EXISTS ckpt_insert ON audit_checkpoints;
CREATE POLICY ckpt_insert ON audit_checkpoints FOR INSERT TO shield_writer WITH CHECK (true);
DROP POLICY IF EXISTS ckpt_read ON audit_checkpoints;
CREATE POLICY ckpt_read ON audit_checkpoints FOR SELECT TO shield_auditor USING (true);

REVOKE ALL ON audit_log, audit_checkpoints FROM PUBLIC;
GRANT INSERT ON audit_log, audit_checkpoints TO shield_writer;
GRANT SELECT ON audit_log, audit_checkpoints TO shield_auditor;
