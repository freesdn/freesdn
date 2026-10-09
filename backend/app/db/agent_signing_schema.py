# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""PostgreSQL invariants for the installation signing journal and active identity.

These guards enforce record relationships, not administrator authentication,
cryptographic key validity, private-file durability or successful agent delivery.
The migration carries a frozen copy; future edits need their own migration.
"""

SIGNING_SCHEMA_DDL = (
    """
CREATE FUNCTION agents.guard_signing_lifecycle() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $signing$
DECLARE intent agents.agent_signing_intents%ROWTYPE;
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'Signing identity and operation history cannot be deleted'
            USING ERRCODE = 'check_violation';
    END IF;
    IF TG_TABLE_NAME = 'agent_signing_identities' THEN
        IF TG_OP = 'UPDATE' THEN
            IF NEW IS DISTINCT FROM OLD THEN
                RAISE EXCEPTION 'Active signing identity is immutable'
                    USING ERRCODE = 'check_violation';
            END IF;
            RETURN NEW;
        END IF;
        SELECT * INTO intent FROM agents.agent_signing_intents
            WHERE operation_id = NEW.operation_id FOR UPDATE;
        IF NOT FOUND OR intent.state IS DISTINCT FROM 'activated'
            OR ROW(NEW.installation_id, NEW.identity_epoch, NEW.public_key_pem,
                   NEW.public_key_sha256, NEW.activated_by, NEW.activated_at)
               IS DISTINCT FROM
               ROW(intent.installation_id, intent.identity_epoch, intent.public_key_pem,
                   intent.public_key_sha256, intent.closed_by, intent.closed_at) THEN
            RAISE EXCEPTION 'Signing identity does not match its activated intent'
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'pending' THEN
            RAISE EXCEPTION 'Signing intent must begin pending'
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW IS NOT DISTINCT FROM OLD THEN
        RETURN NEW;
    END IF;
    IF ROW(NEW.operation_id, NEW.singleton_id, NEW.installation_id, NEW.identity_epoch,
           NEW.kind, NEW.expected_public_sha256, NEW.requested_by, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.operation_id, OLD.singleton_id, OLD.installation_id, OLD.identity_epoch,
           OLD.kind, OLD.expected_public_sha256, OLD.requested_by, OLD.created_at)
       OR OLD.state IN ('activated', 'cancelled')
       OR NOT ((OLD.state = 'pending' AND NEW.state IN ('prepared', 'cancelled'))
               OR (OLD.state = 'prepared' AND NEW.state IN ('activated', 'cancelled')))
       OR (OLD.state = 'prepared' AND
           ROW(NEW.public_key_pem, NEW.public_key_sha256, NEW.prepared_at)
           IS DISTINCT FROM ROW(OLD.public_key_pem, OLD.public_key_sha256, OLD.prepared_at))
       OR (OLD.state = 'pending' AND NEW.state = 'cancelled' AND
           ROW(NEW.public_key_pem, NEW.public_key_sha256, NEW.prepared_at)
           IS DISTINCT FROM ROW(OLD.public_key_pem, OLD.public_key_sha256, OLD.prepared_at)) THEN
        RAISE EXCEPTION 'Signing intent transition would rewrite retained history'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$signing$
""",
    """
CREATE FUNCTION agents.require_activated_signing_identity() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $signing$
DECLARE
    intent agents.agent_signing_intents%ROWTYPE;
    deadline text;
BEGIN
    deadline := current_setting('freesdn.signing_deadline', true);
    IF deadline IS NOT NULL AND deadline <> '' THEN
        IF deadline !~ '^[0-9]{1,12}$' OR
           clock_timestamp() >= to_timestamp(deadline::double precision) THEN
            RAISE EXCEPTION 'Fresh signing confirmation expired before deferred commit validation'
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    SELECT * INTO STRICT intent FROM agents.agent_signing_intents
        WHERE operation_id = NEW.operation_id;
    IF intent.state = 'activated' AND NOT EXISTS (
        SELECT 1 FROM agents.agent_signing_identities i
        WHERE i.operation_id = intent.operation_id
          AND ROW(i.installation_id, i.identity_epoch, i.public_key_pem,
                  i.public_key_sha256, i.activated_by, i.activated_at)
              IS NOT DISTINCT FROM
              ROW(intent.installation_id, intent.identity_epoch, intent.public_key_pem,
                  intent.public_key_sha256, intent.closed_by, intent.closed_at)
    ) THEN
        RAISE EXCEPTION 'Activated signing intent requires its matching identity at commit'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NULL;
END;
$signing$
""",
    """CREATE TRIGGER signing_intent_guard
BEFORE INSERT OR UPDATE OR DELETE ON agents.agent_signing_intents
FOR EACH ROW EXECUTE FUNCTION agents.guard_signing_lifecycle()""",
    """CREATE TRIGGER signing_intent_no_truncate
BEFORE TRUNCATE ON agents.agent_signing_intents
FOR EACH STATEMENT EXECUTE FUNCTION agents.guard_signing_lifecycle()""",
    """CREATE TRIGGER signing_identity_guard
BEFORE INSERT OR UPDATE OR DELETE ON agents.agent_signing_identities
FOR EACH ROW EXECUTE FUNCTION agents.guard_signing_lifecycle()""",
    """CREATE TRIGGER signing_identity_no_truncate
BEFORE TRUNCATE ON agents.agent_signing_identities
FOR EACH STATEMENT EXECUTE FUNCTION agents.guard_signing_lifecycle()""",
    """CREATE CONSTRAINT TRIGGER signing_activation_complete
AFTER INSERT OR UPDATE ON agents.agent_signing_intents
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
EXECUTE FUNCTION agents.require_activated_signing_identity()""",
)
