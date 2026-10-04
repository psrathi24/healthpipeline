"""Dagster jobs and schedules for the denial EOB pipeline."""

from dagster import AssetSelection, ScheduleDefinition, define_asset_job

from pipeline.assets import (
    clean_denial_records,
    prior_auth_contexts,
    raw_eob_data,
    raw_order_data,
)

# Asset job: materialize extract → transform in dependency order
denial_pipeline_job = define_asset_job(
    name="denial_pipeline_job",
    selection=AssetSelection.assets(raw_eob_data, clean_denial_records),
)

completeness_pipeline_job = define_asset_job(
    name="completeness_pipeline_job",
    selection=AssetSelection.assets(raw_order_data, prior_auth_contexts),
)

# Daily at 00:00 (cron: minute hour day month weekday)
nightly_schedule = ScheduleDefinition(
    job=denial_pipeline_job,
    cron_schedule="0 0 * * *",
)

nightly_completeness_schedule = ScheduleDefinition(
    job=completeness_pipeline_job,
    cron_schedule="15 0 * * *",
)