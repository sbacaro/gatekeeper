"""Intentionally insecure module for testing Gatekeeper's secret detection.

DO NOT copy any value from this file into a real project - every credential
below is a fake, revocable example used to exercise the scanners.
"""
import os

# Real hardcoded credentials (fake values, but structurally realistic)
GITHUB_TOKEN = "ghp_9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a"
STRIPE_KEY = "sk_test_51FakeExampleKey00000000000000000000"
DB_PASSWORD = "sup3rs3cret-p4ssw0rd-prod"
JWT_SECRET = "xK9$mQ2#vL8pZ4nR7tW3jY6hF1dG5sB0"

# Fine: loaded from the environment (should NOT be flagged)
AWS_SECRET_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
SESSION_COOKIE_KEY = os.environ["SESSION_COOKIE_KEY"]
