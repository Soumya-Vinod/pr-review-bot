"""Webhook intake: verify X-Hub-Signature-256 against GITHUB_WEBHOOK_SECRET and
decide which GitHub events (e.g. pull_request opened/synchronize) become review jobs.
"""
