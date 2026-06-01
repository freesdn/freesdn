# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - LLM Action Handlers for Automation Engine
=========================================================

Provides three action handlers that bridge the automation engine with
the LLM governance layer:

- LLM_CLASSIFY: Classify event data into labels
- LLM_EXTRACT: Extract structured JSON from event context
- LLM_SUMMARIZE: Produce a text summary of event data

Each handler:
1. Validates input parameters (fields, labels, schema, etc.)
2. Extracts ``input_fields`` from the automation context (dot-notation)
3. Calls ``governance.execute_structured()`` which enforces all 3 governance layers
4. Returns an ``ActionResult`` with the LLM output
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from app.services.automation import AutomationEngine

logger = logging.getLogger(__name__)

# ── Validation constants ─────────────────────────────────────────────────────

MAX_INPUT_FIELDS = 20
MAX_FIELD_PATH_DEPTH = 5
MAX_LABELS = 20
MAX_LABEL_LENGTH = 100
FIELD_PATH_PATTERN = re.compile(r"^[a-zA-Z0-9_][a-zA-Z0-9_.\-]*$")


def _validate_input_fields(input_fields: Any) -> list[str]:
    """Validate input_fields parameter is a safe list of dot-notation paths."""
    if not isinstance(input_fields, list):
        raise ValueError("input_fields must be a list of strings")
    if not input_fields:
        raise ValueError("input_fields must not be empty")
    if len(input_fields) > MAX_INPUT_FIELDS:
        raise ValueError(f"Too many input_fields (max {MAX_INPUT_FIELDS})")
    for path in input_fields:
        if not isinstance(path, str):
            raise ValueError(f"input_fields entries must be strings, got {type(path).__name__}")
        if not FIELD_PATH_PATTERN.match(path):
            raise ValueError(f"Invalid field path: '{path}'")
        if path.count(".") >= MAX_FIELD_PATH_DEPTH:
            raise ValueError(f"Field path too deep: '{path}' (max {MAX_FIELD_PATH_DEPTH} levels)")
    return input_fields


def _validate_labels(labels: Any) -> list[str]:
    """Validate labels for classification."""
    if not isinstance(labels, list):
        raise ValueError("labels must be a list of strings")
    if len(labels) < 2:
        raise ValueError("At least 2 labels required for classification")
    if len(labels) > MAX_LABELS:
        raise ValueError(f"Too many labels (max {MAX_LABELS})")
    safe_labels = []
    for label in labels:
        if not isinstance(label, str):
            raise ValueError(f"Labels must be strings, got {type(label).__name__}")
        # Sanitize: strip and truncate
        clean = label.strip()[:MAX_LABEL_LENGTH]
        if not clean:
            raise ValueError("Labels must not be empty")
        safe_labels.append(clean)
    return safe_labels


# ── Handlers ─────────────────────────────────────────────────────────────────


async def handle_llm_classify(params: dict[str, Any]) -> dict[str, Any]:
    """
    Automation action handler for LLM_CLASSIFY.

    Expected params:
        input_fields: list[str]   — Dot-notation paths into __context__
        labels: list[str]         — Classification labels (2-20)
        provider: str | None      — Override provider (defaults to org default)
    """
    context = params.get("__context__", {})
    provider = params.get("provider")

    try:
        input_fields = _validate_input_fields(params.get("input_fields", []))
        labels = _validate_labels(params.get("labels", []))
    except ValueError as e:
        return {"error": str(e)}

    # Extract field values from context (only from trigger_data subtree)
    input_data = _extract_fields(context, input_fields)
    input_data["_labels"] = ", ".join(labels)

    # Get org_id from context
    org_id = _get_org_id(context)
    if not org_id:
        return {"error": "Organization ID not available in context"}

    from app.db import async_session_factory
    from app.modules.ai.governance import LLMOperation, governance

    async with async_session_factory() as db:
        try:
            result = await governance.execute_structured(
                db=db,
                org_id=org_id,
                operation=LLMOperation.CLASSIFY,
                input_data=input_data,
                provider_id=provider,
                rule_id=_get_uuid(context, "rule_id"),
                execution_id=_get_uuid(context, "execution_id"),
            )
            await db.commit()
            return {
                "classification": result.get("result", "").strip(),
                "tokens_used": result.get("tokens_used", 0),
                "model": result.get("model", ""),
            }
        except Exception as e:
            logger.warning("LLM classify action failed: %s", e)
            return {"error": "LLM classification failed. Check server logs for details."}


async def handle_llm_extract(params: dict[str, Any]) -> dict[str, Any]:
    """
    Automation action handler for LLM_EXTRACT.

    Expected params:
        input_fields: list[str]     — Dot-notation paths into __context__
        output_schema: dict          — JSON Schema for extraction
        provider: str | None         — Override provider
    """
    context = params.get("__context__", {})
    output_schema = params.get("output_schema", {})
    provider = params.get("provider")

    try:
        input_fields = _validate_input_fields(params.get("input_fields", []))
    except ValueError as e:
        return {"error": str(e)}

    # Validate output_schema size (max 10 top-level properties)
    if isinstance(output_schema, dict):
        props = output_schema.get("properties", {})
        if len(props) > 10:
            return {"error": "output_schema must have at most 10 properties"}
    else:
        return {"error": "output_schema must be a dict"}

    input_data = _extract_fields(context, input_fields)
    input_data["_output_schema"] = str(output_schema)

    org_id = _get_org_id(context)
    if not org_id:
        return {"error": "Organization ID not available in context"}

    from app.db import async_session_factory
    from app.modules.ai.governance import LLMOperation, governance

    async with async_session_factory() as db:
        try:
            result = await governance.execute_structured(
                db=db,
                org_id=org_id,
                operation=LLMOperation.EXTRACT,
                input_data=input_data,
                provider_id=provider,
                rule_id=_get_uuid(context, "rule_id"),
                execution_id=_get_uuid(context, "execution_id"),
            )
            await db.commit()

            # Try to parse JSON from response
            import json

            raw = result.get("result", "").strip()
            try:
                extracted = json.loads(raw)
            except json.JSONDecodeError:
                extracted = raw

            return {
                "extracted": extracted,
                "tokens_used": result.get("tokens_used", 0),
                "model": result.get("model", ""),
            }
        except Exception as e:
            logger.warning("LLM extract action failed: %s", e)
            return {"error": "LLM extraction failed. Check server logs for details."}


async def handle_llm_summarize(params: dict[str, Any]) -> dict[str, Any]:
    """
    Automation action handler for LLM_SUMMARIZE.

    Expected params:
        input_fields: list[str]   — Dot-notation paths into __context__
        max_words: int             — Max summary length (default 200)
        provider: str | None       — Override provider
    """
    context = params.get("__context__", {})
    provider = params.get("provider")

    try:
        input_fields = _validate_input_fields(params.get("input_fields", []))
    except ValueError as e:
        return {"error": str(e)}

    # Validate max_words is an integer in range (prevents prompt injection)
    raw_max_words = params.get("max_words", 200)
    if not isinstance(raw_max_words, int):
        try:
            raw_max_words = int(raw_max_words)
        except (ValueError, TypeError):
            raw_max_words = 200
    max_words = max(50, min(raw_max_words, 500))

    input_data = _extract_fields(context, input_fields)
    input_data["_max_words"] = str(max_words)

    org_id = _get_org_id(context)
    if not org_id:
        return {"error": "Organization ID not available in context"}

    from app.db import async_session_factory
    from app.modules.ai.governance import LLMOperation, governance

    async with async_session_factory() as db:
        try:
            result = await governance.execute_structured(
                db=db,
                org_id=org_id,
                operation=LLMOperation.SUMMARIZE,
                input_data=input_data,
                provider_id=provider,
                rule_id=_get_uuid(context, "rule_id"),
                execution_id=_get_uuid(context, "execution_id"),
            )
            await db.commit()
            return {
                "summary": result.get("result", "").strip(),
                "tokens_used": result.get("tokens_used", 0),
                "model": result.get("model", ""),
            }
        except Exception as e:
            logger.warning("LLM summarize action failed: %s", e)
            return {"error": "LLM summarization failed. Check server logs for details."}


def register_llm_handlers(engine: AutomationEngine) -> None:
    """Register all LLM action handlers with the automation engine."""
    from app.services.automation import ActionType

    engine.register_action_handler(ActionType.LLM_CLASSIFY, handle_llm_classify)
    engine.register_action_handler(ActionType.LLM_EXTRACT, handle_llm_extract)
    engine.register_action_handler(ActionType.LLM_SUMMARIZE, handle_llm_summarize)
    logger.info("LLM automation action handlers registered")


# =============================================================================
# Helpers
# =============================================================================

#: Keys that should not be accessible via field extraction
_RESTRICTED_KEYS = frozenset(
    {
        "organization_id",
        "rule_id",
        "execution_id",
        "__context__",
        "password",
        "secret",
        "token",
        "api_key",
        "credential",
    }
)


def _extract_fields(context: dict[str, Any], field_paths: list[str]) -> dict[str, str]:
    """Extract values from context using dot-notation paths, truncated to 1000 chars.

    Only extracts from the trigger_data subtree to prevent access to
    internal context metadata like organization_id, rule_id, etc.
    """
    result = {}
    # Prefer extracting from trigger_data subtree for isolation
    data_root = context.get("trigger_data", context)

    for path in field_paths:
        # Skip restricted paths
        first_segment = path.split(".")[0]
        if first_segment.lower() in _RESTRICTED_KEYS:
            continue
        value = _get_nested(data_root, path)
        if value is not None:
            result[path] = str(value)[:1000]
    return result


def _get_nested(data: dict[str, Any], path: str) -> Any:
    """Get a value from a nested dict using dot notation."""
    parts = path.split(".")
    current = data
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _get_org_id(context: dict[str, Any]) -> UUID | None:
    """Extract organization_id from automation context."""
    org_id = context.get("organization_id")
    if org_id is None:
        return None
    if isinstance(org_id, UUID):
        return org_id
    if isinstance(org_id, str):
        try:
            return UUID(org_id)
        except ValueError:
            return None
    return None  # Reject non-UUID, non-string types


def _get_uuid(context: dict[str, Any], key: str) -> UUID | None:
    """Extract a UUID from context, or None."""
    val = context.get(key)
    if val is None:
        return None
    if isinstance(val, UUID):
        return val
    if isinstance(val, str):
        try:
            return UUID(val)
        except ValueError:
            return None
    return None
