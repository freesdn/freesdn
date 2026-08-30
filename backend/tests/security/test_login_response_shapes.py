# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A ``response_model`` is a whitelist, and /auth/login has two 200 shapes.

``POST /auth/login`` returns a challenge instead of a session when the account
has MFA enabled. It was declared ``response_model=BrowserAuthResponse`` -- the
slim model added when raw tokens were taken out of the JSON body -- and that
model requires ``expires_in``, which the challenge branch does not send. FastAPI
VALIDATES an endpoint's return value against its response model, so the branch
raised ResponseValidationError and answered **500**: every MFA-enabled user was
locked out of the browser login entirely.

Nothing caught it because every existing auth test calls the ``login``
coroutine directly (``await login(request, response, data, session)``), and
calling the function skips the response model completely. The tests here run
FastAPI's own ``serialize_response`` against the route's real ``response_field``
instead, which is the step that was failing.

The same whitelist is why the frontend's forced-password-change flow could
never fire: an undeclared key is not an error, it is DROPPED, silently, with a
200. ``data.force_password_change`` read ``undefined`` on every login for three
releases because no response model declared it. Hence the parametrized test --
any dict an auth endpoint returns must be fully expressible by its declared
response model, or part of it is going nowhere.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import types
import typing
from pathlib import Path

import pytest
from fastapi.routing import APIRoute, serialize_response
from pydantic import BaseModel

from app.api.v1.endpoints.auth import router
from app.schemas.core import BrowserAuthResponse, MfaChallengeResponse

AUTH_SOURCE = Path(inspect.getfile(router.routes[0].endpoint))  # type: ignore[attr-defined]


def _route(path: str) -> APIRoute:
    return next(r for r in router.routes if isinstance(r, APIRoute) and r.path == path)


def _serialize(route: APIRoute, payload: object) -> object:
    """Run the exact validation step FastAPI performs on an endpoint's return value.

    ``get_request_handler`` hands the raw return value straight to
    ``serialize_response`` with the route's own ``response_field``; that call is
    where the MFA branch raised. ``dump_json`` is left False only so the result
    is a comparable dict instead of JSON bytes -- the validation being exercised
    is identical either way.
    """
    return asyncio.run(
        serialize_response(
            field=route.response_field,
            response_content=payload,
            exclude_unset=route.response_model_exclude_unset,
            exclude_defaults=route.response_model_exclude_defaults,
            exclude_none=route.response_model_exclude_none,
            is_coroutine=True,
        )
    )


def test_login_mfa_challenge_survives_its_response_model() -> None:
    """The MFA branch must reach the browser, not ResponseValidationError.

    Mutation this catches: drop ``| MfaChallengeResponse`` from the /login
    response_model and this fails with the original ResponseValidationError on
    the missing ``expires_in``.
    """
    route = _route("/login")
    body = _serialize(route, MfaChallengeResponse(require_mfa=True, mfa_token="pending.jwt.value"))
    assert body == {"require_mfa": True, "mfa_token": "pending.jwt.value"}, (
        "The MFA challenge did not survive /auth/login's response model. A user "
        "with MFA enabled cannot sign in at all when this is wrong."
    )


def test_login_success_still_carries_no_bearer_secrets() -> None:
    """Widening the model must not have re-opened.

    The union has to keep the success body exactly as slim as it was: cookies
    carry the tokens, the JSON body carries nothing bearer-usable.
    """
    body = _serialize(_route("/login"), BrowserAuthResponse(expires_in=900))
    assert body == {"token_type": "bearer", "expires_in": 900}, (
        "The /auth/login success body changed shape. It must stay "
        "token_type + expires_in only -- no access_token, no refresh_token."
    )


def _model_members(model: object) -> list[type[BaseModel]]:
    """Flatten an ``A | B`` response model into its concrete members."""
    if typing.get_origin(model) in (types.UnionType, typing.Union):
        args = typing.get_args(model)
        return [m for m in args if isinstance(m, type) and issubclass(m, BaseModel)]
    if isinstance(model, type) and issubclass(model, BaseModel):
        return [model]
    return []


def _returned_dict_literals(
    func: ast.AsyncFunctionDef | ast.FunctionDef,
) -> list[tuple[int, set[str]]]:
    """Every ``return {"k": ...}`` in this function, excluding nested defs."""
    out: list[tuple[int, set[str]]] = []
    stack: list[ast.AST] = list(func.body)
    while stack:
        node = stack.pop()
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            continue  # a nested helper returns to its caller, not to FastAPI
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict):
            keys = node.value.keys
            if keys and all(isinstance(k, ast.Constant) and isinstance(k.value, str) for k in keys):
                out.append((node.lineno, {k.value for k in keys}))  # type: ignore[union-attr]
        stack.extend(ast.iter_child_nodes(node))
    return out


def _endpoints_with_a_response_model() -> list[tuple[str, APIRoute, ast.AST]]:
    tree = ast.parse(AUTH_SOURCE.read_text(encoding="utf-8"))
    by_name = {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    }
    found: list[tuple[str, APIRoute, ast.AST]] = []
    for route in router.routes:
        # An endpoint with no response_model= gets ``typing.Any`` inferred from
        # its ``-> Any`` return annotation, and Any is not a whitelist -- there
        # is nothing to drop and nothing to require. Only the routes that
        # actually declare a pydantic model are in scope.
        if not isinstance(route, APIRoute) or not _model_members(route.response_model):
            continue
        node = by_name.get(route.endpoint.__name__)
        if node is not None:
            found.append((route.endpoint.__name__, route, node))
    return found


@pytest.mark.parametrize(
    ("name", "route", "node"),
    [pytest.param(*t, id=t[0]) for t in _endpoints_with_a_response_model()],
)
def test_returned_dicts_are_expressible_by_the_response_model(
    name: str, route: APIRoute, node: ast.AST
) -> None:
    """A dict return under a response model must match one member exactly.

    Two ways this goes wrong, both silent, both shipped:

    * a key the model does not declare is DROPPED (200, field simply absent) --
      that is ``force_password_change``;
    * a required field the dict omits is a ResponseValidationError **500** --
      that was the MFA challenge.

    Mutation this catches: put ``return {"require_mfa": True, "mfa_token":
    mfa_token}`` back in ``login`` and this fails on the missing ``expires_in``.
    """
    members = _model_members(route.response_model)

    for lineno, keys in _returned_dict_literals(node):  # type: ignore[arg-type]
        problems = []
        for member in members:
            declared = set(member.model_fields)
            required = {n for n, f in member.model_fields.items() if f.is_required()}
            dropped = keys - declared
            missing = required - keys
            if not dropped and not missing:
                break
            problems.append(
                f"{member.__name__}: dropped={sorted(dropped)} missing={sorted(missing)}"
            )
        else:
            pytest.fail(
                f"{AUTH_SOURCE.name}:{lineno} in {name}() returns keys {sorted(keys)}, which no "
                f"member of its response_model can carry. Keys the model does not declare are "
                f"dropped silently with a 200; required fields the dict omits are a 500.\n  "
                + "\n  ".join(problems)
            )
