"""Dagster jobs and schedules for the prior-auth completeness pipeline."""

from dagster import AssetSelection, ScheduleDefinition, define_asset_job

from pipeline.assets import prior_auth_contexts, raw_order_data

completeness_pipeline_job = define_asset_job(
    name="completeness_pipeline_job",
    selection=AssetSelection.assets(raw_order_data, prior_auth_contexts),
)

nightly_completeness_schedule = ScheduleDefinition(
    job=completeness_pipeline_job,
    cron_schedule="15 0 * * *",
)
