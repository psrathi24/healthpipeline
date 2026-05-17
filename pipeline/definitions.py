"""Dagster Definitions for healthpipeline."""

from dagster import Definitions

from pipeline.assets import clean_denial_records, raw_eob_data
from pipeline.jobs import denial_pipeline_job, nightly_schedule

defs = Definitions(
    assets=[raw_eob_data, clean_denial_records],
    jobs=[denial_pipeline_job],
    schedules=[nightly_schedule],
)