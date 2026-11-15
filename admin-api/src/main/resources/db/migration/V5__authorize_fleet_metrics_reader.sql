ALTER TABLE admin_user_roles
    ADD CONSTRAINT ck_admin_user_roles_role_v4
        CHECK (role IN (
            'VIEWER',
            'POLICY_EDITOR',
            'POLICY_SNAPSHOT_READER',
            'FLEET_METRICS_READER',
            'RESOLVER_AGENT',
            'ADMIN'
        ));

ALTER TABLE admin_user_roles
    DROP CONSTRAINT ck_admin_user_roles_role_v3;
