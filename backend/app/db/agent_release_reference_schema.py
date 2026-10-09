# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Persistent managed-reference invariants, installed by online migration 027.

This is not authentication, filesystem proof or a cleanup grant. The only managed
payload address is its immutable owned publication association plus release ID.
Legacy filenames and arbitrary external URLs do not create owned associations.
Old filename/glob readers and writers must be drained/converted before enablement.

Do not attach these triggers to create_all(): frozen migration 025 must first
verify its original journal triggers. Fresh and installed paths both run 027.
Cleanup/delivery must inspect the installed guards, not infer them from models.
"""

REFERENCE_DDL = (
    """CREATE FUNCTION agents.lock_release_references() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $reference_lock$
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'Managed release writers require READ COMMITTED' USING ERRCODE = '23514';
    END IF;
    -- Direct SQL may already own a release RowExclusive lock. NOWAIT on both
    -- tables prevents a waiting upgrade/reversed-order cycle with coordinators.
    LOCK TABLE agents.agent_release_operations IN SHARE ROW EXCLUSIVE MODE NOWAIT;
    LOCK TABLE agents.agent_releases IN SHARE ROW EXCLUSIVE MODE NOWAIT;
    IF TG_OP = 'TRUNCATE' AND EXISTS (
        SELECT 1 FROM agents.agent_release_operations
        WHERE kind = 'publish' AND storage_kind = 'owned'
    ) THEN
        RAISE EXCEPTION 'Managed release history forbids truncation' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$reference_lock$""",
    """CREATE FUNCTION agents.assert_release_reference(identity uuid) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $reference_assert$
DECLARE
    publication agents.agent_release_operations%ROWTYPE;
    live agents.agent_releases%ROWTYPE;
    owned_found boolean;
    live_found boolean;
    deleted boolean;
BEGIN
    SELECT * INTO publication FROM agents.agent_release_operations
    WHERE release_id = identity AND kind = 'publish' AND storage_kind = 'owned';
    owned_found := FOUND;
    -- Every owned deletion, including pending/cancelled ones, retains its exact
    -- original publication. Unknown history is not an artifact identity.
    IF EXISTS (
        SELECT 1 FROM agents.agent_release_operations d
        WHERE d.release_id = identity AND d.kind = 'delete' AND d.storage_kind = 'owned'
          AND (NOT owned_found OR publication.phase IS DISTINCT FROM 'decided'
               OR publication.decision IS DISTINCT FROM 'published'
               OR d.operation_id = publication.operation_id
               OR ROW(d.organization_id, d.artifact_id, d.expected_sha256, d.expected_size)
                  IS DISTINCT FROM ROW(publication.organization_id, publication.artifact_id,
                                       publication.expected_sha256, publication.expected_size))
    ) THEN
        RAISE EXCEPTION 'Managed deletion has no exact publication' USING ERRCODE = '23514';
    END IF;
    IF NOT owned_found THEN
        RETURN;
    END IF;
    IF EXISTS (
        SELECT 1 FROM agents.agent_release_operations d
        WHERE d.release_id = identity AND d.kind = 'delete'
          AND (d.storage_kind IS DISTINCT FROM 'owned'
               OR ROW(d.organization_id, d.artifact_id, d.expected_sha256, d.expected_size)
                  IS DISTINCT FROM ROW(publication.organization_id, publication.artifact_id,
                                       publication.expected_sha256, publication.expected_size))
    ) THEN
        RAISE EXCEPTION 'Managed history has a conflicting deletion' USING ERRCODE = '23514';
    END IF;
    SELECT * INTO live FROM agents.agent_releases WHERE id = identity;
    live_found := FOUND;
    SELECT EXISTS (
        SELECT 1 FROM agents.agent_release_operations
        WHERE release_id = identity AND kind = 'delete' AND decision = 'deleted'
          AND phase IN ('decided', 'cleaned')
    ) INTO deleted;
    IF live_found THEN
        IF publication.phase IS DISTINCT FROM 'decided'
           OR publication.decision IS DISTINCT FROM 'published' OR deleted
           OR live.organization_id IS DISTINCT FROM publication.organization_id
           OR live.checksum_sha256 IS DISTINCT FROM publication.expected_sha256
           OR live.file_size IS DISTINCT FROM publication.expected_size
           OR live.download_url IS DISTINCT FROM '/api/v1/agents/releases/' || identity::text || '/binary'
           OR live.filename IS NULL OR live.filename = '' THEN
            RAISE EXCEPTION 'Managed release reference is not live and exact' USING ERRCODE = '23514';
        END IF;
    ELSIF publication.phase = 'decided' AND publication.decision = 'published' AND NOT deleted THEN
        RAISE EXCEPTION 'Managed release removal requires its deletion decision' USING ERRCODE = '23514';
    END IF;
END
$reference_assert$""",
    """CREATE FUNCTION agents.check_release_references() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $reference_check$
BEGIN
    -- Deferred row events inspect FINAL transaction state, not an intermediate
    -- INSERT before its journal publication or DELETE before its decision.
    IF TG_TABLE_NAME = 'agent_releases' THEN
        IF TG_OP <> 'INSERT' THEN
            PERFORM agents.assert_release_reference(OLD.id);
        END IF;
        IF TG_OP <> 'DELETE' THEN
            PERFORM agents.assert_release_reference(NEW.id);
        END IF;
    ELSE
        IF TG_OP <> 'INSERT' THEN
            PERFORM agents.assert_release_reference(OLD.release_id);
        END IF;
        IF TG_OP <> 'DELETE' THEN
            PERFORM agents.assert_release_reference(NEW.release_id);
        END IF;
    END IF;
    RETURN NULL;
END
$reference_check$""",
    """CREATE TRIGGER release_reference_writer_fence BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE
ON agents.agent_releases FOR EACH STATEMENT EXECUTE FUNCTION agents.lock_release_references()""",
    """CREATE TRIGGER operation_reference_writer_fence BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE
ON agents.agent_release_operations FOR EACH STATEMENT EXECUTE FUNCTION agents.lock_release_references()""",
    """CREATE CONSTRAINT TRIGGER release_reference_deferred AFTER INSERT OR UPDATE OR DELETE
ON agents.agent_releases DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION agents.check_release_references()""",
    """CREATE CONSTRAINT TRIGGER operation_reference_deferred AFTER INSERT OR UPDATE OR DELETE
ON agents.agent_release_operations DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION agents.check_release_references()""",
)
