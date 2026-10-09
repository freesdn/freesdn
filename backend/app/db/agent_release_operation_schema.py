# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Retained release-operation decisions; no filesystem or authorization proof.

Unknown commit outcome is an observation, not a terminal failure state. Callers
must inspect the same operation under coordination before acting on files. This
journal does not itself authorize a transition or verify the associated release.
"""

RELEASE_OPERATION_CHECKS = (
    ("format", "format_version = 1"),
    ("kind", "kind IN ('publish', 'delete')"),
    (
        "storage",
        "storage_kind IN ('owned', 'external', 'legacy') AND "
        "((storage_kind = 'owned' AND artifact_id IS NOT NULL) OR "
        "(storage_kind IN ('external', 'legacy') AND artifact_id IS NULL)) AND "
        "(kind = 'delete' OR storage_kind <> 'legacy') AND "
        "(kind <> 'publish' OR storage_kind <> 'owned' OR artifact_id = operation_id)",
    ),
    (
        "request_binding",
        "octet_length(request_bytes) BETWEEN 1 AND 65536 AND "
        "request_sha256 = encode(sha256(request_bytes), 'hex')",
    ),
    (
        "artifact_binding",
        "expected_sha256 ~ '^[0-9a-f]{64}$' AND "
        "expected_size BETWEEN 0 AND 10737418240 AND "
        "(storage_kind <> 'owned' OR expected_size <= 524288000)",
    ),
    ("sequence", "transition_sequence BETWEEN 0 AND 3"),
    ("phase", "phase IN ('reserved', 'prepared', 'decided', 'cleaned')"),
    (
        "decision_kind",
        "decision IS NULL OR decision = 'cancelled' OR "
        "(kind = 'publish' AND decision = 'published') OR "
        "(kind = 'delete' AND decision = 'deleted')",
    ),
    (
        "phase_fields",
        "(phase = 'reserved' AND transition_sequence = 0 AND prepared_at IS NULL "
        "AND decision IS NULL AND decided_at IS NULL AND cleaned_at IS NULL) OR "
        "(phase = 'prepared' AND transition_sequence = 1 AND prepared_at IS NOT NULL "
        "AND decision IS NULL AND decided_at IS NULL AND cleaned_at IS NULL) OR "
        "(phase = 'decided' AND decision IS NOT NULL AND decided_at IS NOT NULL "
        "AND cleaned_at IS NULL AND ((prepared_at IS NOT NULL AND transition_sequence = 2) OR "
        "(prepared_at IS NULL AND transition_sequence = 1 AND decision = 'cancelled'))) OR "
        "(phase = 'cleaned' AND decision IS NOT NULL AND decision IN ('deleted', 'cancelled') AND decided_at IS NOT NULL "
        "AND cleaned_at IS NOT NULL AND ((prepared_at IS NOT NULL AND transition_sequence = 3) OR "
        "(prepared_at IS NULL AND transition_sequence = 2 AND decision = 'cancelled')))",
    ),
    (
        "time_order",
        "(prepared_at IS NULL OR prepared_at >= created_at) AND "
        "(decided_at IS NULL OR decided_at >= created_at) AND "
        "(prepared_at IS NULL OR decided_at IS NULL OR decided_at >= prepared_at) AND "
        "(cleaned_at IS NULL OR cleaned_at >= decided_at)",
    ),
)

RELEASE_OPERATION_DDL = (
    """CREATE FUNCTION agents.guard_release_operation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $release_operation$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'Release operation history must be retained' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.phase IS DISTINCT FROM 'reserved' OR NEW.transition_sequence IS DISTINCT FROM 0
           OR NEW.last_transition_by IS DISTINCT FROM NEW.requested_by THEN
            RAISE EXCEPTION 'Release operation must begin reserved' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW IS NOT DISTINCT FROM OLD THEN
        RETURN NEW;
    END IF;
    IF ROW(NEW.operation_id, NEW.format_version, NEW.kind, NEW.release_id,
           NEW.organization_id, NEW.requested_by, NEW.storage_kind, NEW.artifact_id,
           NEW.request_bytes, NEW.request_sha256, NEW.expected_sha256, NEW.expected_size,
           NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.operation_id, OLD.format_version, OLD.kind, OLD.release_id,
           OLD.organization_id, OLD.requested_by, OLD.storage_kind, OLD.artifact_id,
           OLD.request_bytes, OLD.request_sha256, OLD.expected_sha256, OLD.expected_size,
           OLD.created_at) THEN
        RAISE EXCEPTION 'Release operation intent is immutable' USING ERRCODE = '23514';
    END IF;
    IF NEW.transition_sequence IS DISTINCT FROM OLD.transition_sequence + 1
       OR (OLD.prepared_at IS NOT NULL AND NEW.prepared_at IS DISTINCT FROM OLD.prepared_at)
       OR (OLD.decided_at IS NOT NULL AND NEW.decided_at IS DISTINCT FROM OLD.decided_at)
       OR (OLD.decision IS NOT NULL AND NEW.decision IS DISTINCT FROM OLD.decision)
       OR (OLD.cleaned_at IS NOT NULL AND NEW.cleaned_at IS DISTINCT FROM OLD.cleaned_at) THEN
        RAISE EXCEPTION 'Release operation cannot rewind or rewrite a decision' USING ERRCODE = '23514';
    END IF;
    IF NOT (
        (OLD.phase = 'reserved' AND NEW.phase = 'prepared') OR
        (OLD.phase IN ('reserved', 'prepared') AND NEW.phase = 'decided'
         AND NEW.decision = 'cancelled') OR
        (OLD.phase = 'prepared' AND NEW.phase = 'decided'
         AND ((OLD.kind = 'publish' AND NEW.decision = 'published') OR
              (OLD.kind = 'delete' AND NEW.decision = 'deleted'))) OR
        (OLD.phase = 'decided' AND OLD.decision IN ('deleted', 'cancelled')
         AND NEW.phase = 'cleaned')
    ) THEN
        RAISE EXCEPTION 'Release operation transition refused' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$release_operation$""",
    """CREATE TRIGGER guard_release_operation BEFORE INSERT OR UPDATE OR DELETE
ON agents.agent_release_operations FOR EACH ROW EXECUTE FUNCTION agents.guard_release_operation()""",
    """CREATE TRIGGER guard_release_operation_no_truncate BEFORE TRUNCATE
ON agents.agent_release_operations FOR EACH STATEMENT EXECUTE FUNCTION agents.guard_release_operation()""",
)
