"""Workflow identifiers shared by portal routers and the pipeline."""

from __future__ import annotations

WORKFLOW_DENIAL = "prior_auth_denial"
WORKFLOW_COMPLETENESS = "prior_auth_completeness"
WORKFLOW_DEFAULT = WORKFLOW_DENIAL

LIVE_WORKFLOWS = (WORKFLOW_COMPLETENESS, WORKFLOW_DENIAL)


def is_completeness(workflow: str | None) -> bool:
    return (workflow or "") == WORKFLOW_COMPLETENESS


def case_table(workflow: str | None) -> str:
    return "prior_auth_contexts" if is_completeness(workflow) else "denial_contexts"
