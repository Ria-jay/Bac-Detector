"""
Replay engine — request building, execution, and throttling.

Public API:
    run_replay(inventory, config)  -> (list[ResponseMeta], ExecutionSummary)
    build_requests(endpoint, identities, object_ids)  -> list[PreparedRequest]
    execute_requests(requests, config)  -> (list[ResponseMeta], ExecutionSummary)
    PreparedRequest
    ExecutorConfig
    ExecutionSummary
"""

from bac_detector.replay.builder import PreparedRequest, build_requests
from bac_detector.replay.executor import ExecutionSummary, ExecutorConfig, execute_requests
from bac_detector.replay.runner import run_replay

__all__ = [
    "ExecutionSummary",
    "ExecutorConfig",
    "PreparedRequest",
    "build_requests",
    "execute_requests",
    "run_replay",
]
