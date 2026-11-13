# Runbook: SpindleBackupStale

## Overview
- **Alert Name**: `SpindleBackupStale`
- **Severity**: `warning`
- **Metric**: `spindle_last_successful_backup_timestamp_seconds`
- **Condition**: the last online backup is older than two days.

## Context
`POST /_spindle/admin/v1/backup` writes a backup to `[storage] backup_dir`. The metric holds the time of the last one that finished in this process.

## Diagnostic Steps
1. Check the job that calls the endpoint, and its admin token.
2. Check the free space in `backup_dir`.
3. Read the audit log (`GET /_spindle/admin/v1/audit`) for `backup` records.

## Mitigation
- Fix the job or free space, then call the endpoint by hand.
