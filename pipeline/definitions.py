"""Dagster Definitions for healthpipeline."""

from dagster import Definitions

from pipeline.assets import prior_auth_contexts, raw_order_data
from pipeline.jobs import completeness_pipeline_job, nightly_completeness_schedule

defs = Definitions(
    assets=[raw_order_data, prior_auth_contexts],
    jobs=[completeness_pipeline_job],
    schedules=[nightly_completeness_schedule],
)
