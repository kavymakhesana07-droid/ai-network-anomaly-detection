#!/usr/bin/env python3
"""
Kali Live Capture - Quick Start Python Script
Alternative to the bash script for environments where bash isn't available.
"""

# ruff: noqa: S404 - subprocess used for docker CLI, not user input
# ruff: noqa: PTH120,PTH118,PTH113 - pathlib.Path used where possible
# ruff: noqa: F401 - imports used for dependency checking only

import argparse
import os
import pathlib
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description="Kali Live Capture Quick Start")
    parser.add_argument("-i", "--interface", default="eth0", help="Network interface")
    parser.add_argument("-b", "--brokers", default="localhost:9092", help="Kafka brokers")
    parser.add_argument("-t", "--topic", default="raw.packets", help="Kafka topic")
    parser.add_argument("--docker", action="store_true", help="Run via Docker")
    parser.add_argument("--build", action="store_true", help="Build Docker image first")
    args = parser.parse_args()

    repo_root = pathlib.Path(__file__).resolve().parent.parent

    if os.geteuid() != 0:
        print("ERROR: Must run as root (sudo) for raw socket access")
        sys.exit(1)

    env = os.environ.copy()
    env.update({
        "KAFKA_BROKERS": args.brokers,
        "TOPIC": args.topic,
        "INTERFACE": args.interface,
        "PROMISC": "true",
        "SNAPLEN": "65535",
        "CHECKPOINT_DIR": "./data/checkpoints",
        "LOG_LEVEL": "INFO",
        "PYTHONPATH": repo_root,
    })

    pathlib.Path(env["CHECKPOINT_DIR"]).mkdir(exist_ok=True, parents=True)

    if args.docker:
        cmd = ["docker", "compose", "build", "live-capture-ingestor"] if args.build else []
        if cmd:
            subprocess.run(cmd, cwd=repo_root, check=True)

        cmd = [
            "docker",
            "run",
            "--rm",
            "--name",
            "anomaly-live-capture",
            "--cap-add=NET_RAW",
            "--cap-add=NET_ADMIN",
            "--network",
            "anomaly-net",
            "-e",
            f"KAFKA_BROKERS={args.brokers}",
            "-e",
            f"TOPIC={args.topic}",
            "-e",
            f"INTERFACE={args.interface}",
            "-e",
            "PROMISC=true",
            "-e",
            "SNAPLEN=65535",
            "-e",
            "CHECKPOINT_DIR=/data/checkpoints",
            "-v",
            f"{pathlib.Path(env['CHECKPOINT_DIR']).resolve()}:/data/checkpoints",
            "anomaly-detection/ingestion-live_capture:latest",
        ]
    else:
        # Check deps - imports used for side-effect only
        try:
            import importlib.util

            for mod in ("aiokafka", "scapy", "structlog"):
                if importlib.util.find_spec(mod) is None:
                    raise ImportError(mod)
        except ImportError:
            print("Installing dependencies...")
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "-r", "requirements/ingest.txt"],
                cwd=repo_root,
                check=True,
            )

        cmd = [sys.executable, "-m", "ingestion.live_capture.main"]

    print(f"Starting live capture on {args.interface} -> Kafka {args.brokers}/{args.topic}")
    try:
        subprocess.run(cmd, cwd=repo_root, env=env, check=True)
    except KeyboardInterrupt:
        print("\nStopped by user")
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        sys.exit(e.returncode)


if __name__ == "__main__":
    main()
