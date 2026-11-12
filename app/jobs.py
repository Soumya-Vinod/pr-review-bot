"""Background job worker: polls the job table, runs reviews, retries failures with
backoff, and keeps processing idempotent per PR head commit.
"""
