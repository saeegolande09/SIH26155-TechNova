import sys
import json
import difflib
import os


def detect_drift(old_file, new_file):

    if not os.path.exists(old_file):
        return {
            "success": False,
            "message": "Old configuration file not found"
        }

    if not os.path.exists(new_file):
        return {
            "success": False,
            "message": "New configuration file not found"
        }

    with open(old_file, "r", encoding="utf-8", errors="ignore") as file:
        old_config = file.readlines()

    with open(new_file, "r", encoding="utf-8", errors="ignore") as file:
        new_config = file.readlines()

    diff = list(
        difflib.unified_diff(
            old_config,
            new_config,
            fromfile="Old Configuration",
            tofile="New Configuration",
            lineterm=""
        )
    )

    added = []
    removed = []

    for line in diff:

        if line.startswith("+++") or line.startswith("---"):
            continue

        if line.startswith("+"):
            added.append(line[1:].strip())

        elif line.startswith("-"):
            removed.append(line[1:].strip())

    changed_lines = len(added) + len(removed)

    security_impact = "None"
    risk_level = "Low"

    combined_changes = " ".join(
        added + removed
    ).lower()

    security_keywords = [
        "telnet",
        "enable password",
        "password",
        "http",
        "ftp",
        "snmp",
        "ssh",
        "access-list",
        "permit",
        "deny"
    ]

    for keyword in security_keywords:

        if keyword in combined_changes:

            security_impact = (
                "Security-related configuration change detected."
            )

            risk_level = "High"

            break

    return {
        "success": True,
        "driftDetected": changed_lines > 0,
        "changedLines": changed_lines,
        "added": added,
        "removed": removed,
        "securityImpact": security_impact,
        "riskLevel": risk_level
    }


if __name__ == "__main__":

    if len(sys.argv) < 3:

        print(json.dumps({
            "success": False,
            "message": "Usage: python drift_detector.py <old_file> <new_file>"
        }))

        sys.exit(1)

    old_file = sys.argv[1]
    new_file = sys.argv[2]

    result = detect_drift(
        old_file,
        new_file
    )

    print(
        json.dumps(
            result,
            indent=2
        )
    )