ALTER TABLE admin_user_roles
    ADD CONSTRAINT ck_admin_user_roles_role_v3
        CHECK (role IN (
            'VIEWER',
            'POLICY_EDITOR',
            'POLICY_SNAPSHOT_READER',
            'RESOLVER_AGENT',
            'ADMIN'
        ));

ALTER TABLE admin_user_roles
    DROP CONSTRAINT ck_admin_user_roles_role_v2;

CREATE TABLE resolver_instances (
    resolver_id VARCHAR(63) PRIMARY KEY,
    identity_user_id BIGINT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    active_session_id VARCHAR(36),
    last_session_generation BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT uk_resolver_instances_identity_user UNIQUE (identity_user_id),
    CONSTRAINT fk_resolver_instances_identity_user
        FOREIGN KEY (identity_user_id) REFERENCES admin_users (id),
    CONSTRAINT ck_resolver_instances_generation
        CHECK (last_session_generation >= 0)
);

CREATE TABLE resolver_sessions (
    session_id VARCHAR(36) PRIMARY KEY,
    resolver_id VARCHAR(63) NOT NULL,
    boot_id VARCHAR(36) NOT NULL,
    session_generation BIGINT NOT NULL,
    application_version VARCHAR(64) NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    superseded_at TIMESTAMP WITH TIME ZONE,
    last_sequence BIGINT,
    policy_mode VARCHAR(16),
    policy_snapshot_loaded BOOLEAN,
    policy_revision BIGINT,
    policy_rule_count INTEGER,
    policy_ready BOOLEAN,
    policy_sync_state VARCHAR(32),
    last_report_received_at TIMESTAMP WITH TIME ZONE,
    version BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT fk_resolver_sessions_resolver
        FOREIGN KEY (resolver_id) REFERENCES resolver_instances (resolver_id),
    CONSTRAINT uk_resolver_sessions_boot UNIQUE (resolver_id, boot_id),
    CONSTRAINT uk_resolver_sessions_generation
        UNIQUE (resolver_id, session_generation),
    CONSTRAINT uk_resolver_sessions_active_reference
        UNIQUE (session_id, resolver_id, session_generation),
    CONSTRAINT ck_resolver_sessions_generation
        CHECK (session_generation >= 1),
    CONSTRAINT ck_resolver_sessions_sequence
        CHECK (last_sequence IS NULL OR last_sequence >= 1),
    CONSTRAINT ck_resolver_sessions_policy_revision
        CHECK (policy_revision IS NULL OR policy_revision >= 0),
    CONSTRAINT ck_resolver_sessions_policy_rule_count
        CHECK (policy_rule_count IS NULL OR policy_rule_count >= 0),
    CONSTRAINT ck_resolver_sessions_policy_mode
        CHECK (policy_mode IS NULL OR policy_mode IN ('DISABLED', 'REQUIRED')),
    CONSTRAINT ck_resolver_sessions_policy_sync_state
        CHECK (
            policy_sync_state IS NULL
            OR policy_sync_state IN (
                'DISABLED',
                'AWAITING_INITIAL_SNAPSHOT',
                'HEALTHY',
                'DEGRADED',
                'STALE'
            )
        ),
    CONSTRAINT ck_resolver_sessions_report_completeness
        CHECK (
            (last_sequence IS NULL
                AND policy_mode IS NULL
                AND policy_snapshot_loaded IS NULL
                AND policy_revision IS NULL
                AND policy_rule_count IS NULL
                AND policy_ready IS NULL
                AND policy_sync_state IS NULL
                AND last_report_received_at IS NULL)
            OR
            (last_sequence IS NOT NULL
                AND policy_mode IS NOT NULL
                AND policy_snapshot_loaded IS NOT NULL
                AND policy_revision IS NOT NULL
                AND policy_rule_count IS NOT NULL
                AND policy_ready IS NOT NULL
                AND policy_sync_state IS NOT NULL
                AND last_report_received_at IS NOT NULL)
        ),
    CONSTRAINT ck_resolver_sessions_policy_state
        CHECK (
            last_sequence IS NULL
            OR (
                policy_mode = 'DISABLED'
                AND policy_snapshot_loaded = FALSE
                AND policy_revision = 0
                AND policy_rule_count = 0
                AND policy_ready = TRUE
                AND policy_sync_state = 'DISABLED'
            )
            OR (
                policy_mode = 'REQUIRED'
                AND policy_snapshot_loaded = FALSE
                AND policy_revision = 0
                AND policy_rule_count = 0
                AND policy_ready = FALSE
                AND policy_sync_state = 'AWAITING_INITIAL_SNAPSHOT'
            )
            OR (
                policy_mode = 'REQUIRED'
                AND policy_snapshot_loaded = TRUE
                AND policy_ready = TRUE
                AND policy_sync_state IN ('HEALTHY', 'DEGRADED', 'STALE')
            )
        )
);

CREATE INDEX idx_resolver_sessions_resolver
    ON resolver_sessions (resolver_id);

ALTER TABLE resolver_instances
    ADD CONSTRAINT fk_resolver_instances_active_session
        FOREIGN KEY (
            active_session_id,
            resolver_id,
            last_session_generation
        ) REFERENCES resolver_sessions (
            session_id,
            resolver_id,
            session_generation
        );
