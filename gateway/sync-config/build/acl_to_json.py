#!/usr/bin/env python3
"""
Parse Mosquitto ACL file into JSON structure for state snapshots.

Output: JSON object like:
{
  "user1": {"readwrite": ["topic1", "topic2"], "read": ["topic3"]},
  "user2": {"readwrite": [], "read": []}
}
"""

import json
import sys
from pathlib import Path

def parse_acl(acl_path: str = "/config/acl") -> dict:
    users: dict[str, dict[str, list[str]]] = {}
    current_user: str | None = None

    path = Path(acl_path)
    if not path.exists():
        return {}

    try:
        with path.open() as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line:
                    continue

                if line.startswith("user "):
                    current_user = line.split(None, 1)[1].strip()
                    if current_user:
                        users[current_user] = {"readwrite": [], "read": []}
                elif line.startswith("topic ") and current_user:
                    # Format: topic <perm> <topic>
                    parts = line.split(None, 2)
                    if len(parts) >= 3:
                        perm = parts[1].lower()
                        topic = parts[2].strip()
                        if perm in ("readwrite", "read") and topic:
                            users[current_user][perm].append(topic)
    except Exception as e:
        print(f"Error parsing ACL: {e}", file=sys.stderr)
        return {}

    return users

if __name__ == "__main__":
    acl_data = parse_acl()
    print(json.dumps(acl_data, indent=0))
