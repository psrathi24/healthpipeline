"""Dagster Definitions for healthpipeline."""

from dagster import Definitions

from pipeline.assets import (
    clean_denial_records,
    prior_auth_contexts,
    raw_eob_data,
    raw_order_data,
)
from pipeline.jobs import (
    completeness_pipeline_job,
    denial_pipeline_job,
    nightly_completeness_schedule,
    nightly_schedule,
)

defs = Definitions(
    assets=[raw_eob_data, clean_denial_records, raw_order_data, prior_auth_contexts],
    jobs=[denial_pipeline_job, completeness_pipeline_job],
    schedules=[nightly_schedule, nightly_completeness_schedule],
)