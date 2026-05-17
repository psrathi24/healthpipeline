"""Dagster jobs and schedules for the denial EOB pipeline."""

from dagster import AssetSelection, ScheduleDefinition, define_asset_job

from pipeline.assets import clean_denial_records, raw_eob_data

# Asset job: materialize extract → transform in dependency order
denial_pipeline_job = define_asset_job(
    name="denial_pipeline_job",
    selection=AssetSelection.assets(raw_eob_data, clean_denial_records),
)

# Daily at 00:00 (cron: minute hour day month weekday)
nightly_schedule = ScheduleDefinition(
    job=denial_pipeline_job,
    cron_schedule="0 0 * * *",
)