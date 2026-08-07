#!/usr/bin/env python3
"""Dispatch one MCP task from the central orchestrator container."""
import argparse
import json

from mcp.core import Priority
from agents.central_orchestrator.main import CentralOrchestrator


def parse_json(value: str):
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise argparse.ArgumentTypeError(f"Invalid JSON: {exc}") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-agent", required=True)
    parser.add_argument("--task-type", required=True)
    parser.add_argument("--parameters", type=parse_json, default={})
    parser.add_argument("--scope", type=parse_json, default=None)
    parser.add_argument("--priority", choices=["critical", "high", "medium", "low", "info"], default="medium")
    args = parser.parse_args()

    priority = {
        "critical": Priority.CRITICAL,
        "high": Priority.HIGH,
        "medium": Priority.MEDIUM,
        "low": Priority.LOW,
        "info": Priority.INFO,
    }[args.priority]

    orchestrator = CentralOrchestrator()
    try:
        message_id = orchestrator.dispatch_task(
            args.target_agent,
            args.task_type,
            args.parameters,
            priority,
            args.scope,
        )
        if not message_id:
            print("Task dispatch failed")
            return 1
        print(message_id)
        return 0
    finally:
        orchestrator.client.stop()


if __name__ == "__main__":
    raise SystemExit(main())
