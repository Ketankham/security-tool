"""Shared substrate for the Sentinel scanner: the four services every scan
phase builds on (docs/01-architecture.md §4.1).

    http_engine    the single outbound choke point
    scope_guard    pre-flight legal/technical boundary enforcement
    rate_limiter   adaptive, per-target, cross-worker throttling
    transcript     content-addressed evidence recording + scrubbing
    state_machine  the persisted scan lifecycle FSM
    crypto         envelope encryption for customer credentials
"""

__version__ = "0.1.0"
