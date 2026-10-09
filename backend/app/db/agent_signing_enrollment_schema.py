# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Public enrollment pin binding; private material is never stored here."""

ENROLLMENT_DDL = (
    """CREATE FUNCTION agents.guard_signing_enrollment() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $enrollment$
DECLARE identity_record record;
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'Enrollment history cannot be truncated' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'DELETE' THEN
        IF EXISTS (SELECT 1 FROM agents.remote_agents WHERE id = OLD.agent_id) THEN
            RAISE EXCEPTION 'Delete the agent through its lifecycle, not its trust pin' USING ERRCODE = '23514';
        END IF;
        RETURN OLD;
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'Enrolled signing identity is immutable' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    SELECT installation_id, identity_epoch, public_key_sha256 INTO identity_record
      FROM agents.agent_signing_identities WHERE singleton_id = 1 FOR SHARE;
    IF NOT FOUND OR NEW.signing_singleton_id IS DISTINCT FROM 1
       OR NEW.installation_id IS DISTINCT FROM identity_record.installation_id
       OR NEW.identity_epoch IS DISTINCT FROM identity_record.identity_epoch
       OR NEW.public_key_sha256 IS DISTINCT FROM identity_record.public_key_sha256 THEN
        RAISE EXCEPTION 'Enrollment requires the active signing identity' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$enrollment$""",
    """CREATE TRIGGER guard_signing_enrollment BEFORE INSERT OR UPDATE OR DELETE
ON agents.agent_signing_enrollments FOR EACH ROW EXECUTE FUNCTION agents.guard_signing_enrollment()""",
    """CREATE TRIGGER guard_signing_enrollment_no_truncate BEFORE TRUNCATE
ON agents.agent_signing_enrollments FOR EACH STATEMENT EXECUTE FUNCTION agents.guard_signing_enrollment()""",
)
