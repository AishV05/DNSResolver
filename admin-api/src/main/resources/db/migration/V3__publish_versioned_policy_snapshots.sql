ALTER TABLE admin_user_roles
    ADD CONSTRAINT ck_admin_user_roles_role_v2
        CHECK (role IN (
            'VIEWER',
            'POLICY_EDITOR',
            'POLICY_SNAPSHOT_READER',
            'ADMIN'
        ));

ALTER TABLE admin_user_roles
    DROP CONSTRAINT ck_admin_user_roles_role;

CREATE TABLE dns_policy_snapshot_state (
    singleton_id INTEGER PRIMARY KEY,
    revision BIGINT NOT NULL,
    published_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT ck_dns_policy_snapshot_singleton
        CHECK (singleton_id = 1),
    CONSTRAINT ck_dns_policy_snapshot_revision
        CHECK (revision >= 0)
);

INSERT INTO dns_policy_snapshot_state (
    singleton_id,
    revision,
    published_at
) VALUES (1, 0, CURRENT_TIMESTAMP);
