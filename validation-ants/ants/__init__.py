"""Validation ants: planner, gatekeeper, observers, matcher and reporter."""

from .oaev_standin import ensure as _ensure_client

# The Splunk observer reuses the splunk-es collector code, which imports a few names from the
# OpenAEV Python client (pyoaev). Where that client is not installed, a small stand-in written for
# this repository takes its place, so the ants still run. The real client always wins.
# See ants/oaev_standin.py.
OAEV_CLIENT = _ensure_client()
