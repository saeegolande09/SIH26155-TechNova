import sys
import json
import os
import re


def analyze_reachability(file_path):

    if not os.path.exists(file_path):
        return {
            "success": False,
            "message": "Configuration file not found"
        }

    with open(
        file_path,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as file:

        config = file.read()

    lines = config.splitlines()

    reachable_rules = []

    for line in lines:

        line = line.strip()

        if not line:
            continue

        lower_line = line.lower()

        # Only analyze permit rules
        if "permit" not in lower_line:
            continue

        source = "Unknown"
        destination = "Unknown"
        service = "Unknown"
        port = None

        # Detect protocol
        if "tcp" in lower_line:
            service = "TCP"

        elif "udp" in lower_line:
            service = "UDP"

        elif "icmp" in lower_line:
            service = "ICMP"


        # Detect source and destination
        parts = lower_line.split()

        try:

            permit_index = parts.index("permit")

            protocol_index = permit_index + 1

            source_index = protocol_index + 1
            destination_index = protocol_index + 2

            if source_index < len(parts):
                source = parts[source_index]

            if destination_index < len(parts):
                destination = parts[destination_index]

        except (ValueError, IndexError):
            pass


        # Detect destination port
        port_match = re.search(
            r"eq\s+(\d+)",
            lower_line
        )

        if port_match:
            port = int(port_match.group(1))


        reachable_rules.append({
            "rule": line,
            "source": source,
            "destination": destination,
            "protocol": service,
            "port": port
        })


    # Determine reachability risk
    risk_level = "Low"

    if reachable_rules:
        risk_level = "Medium"

    for rule in reachable_rules:

        if rule["source"] == "any" and rule["destination"] == "any":

            risk_level = "High"

            break


    return {
        "success": True,
        "totalReachableRules": len(reachable_rules),
        "reachableRules": reachable_rules,
        "riskLevel": risk_level
    }


if __name__ == "__main__":

    if len(sys.argv) < 2:

        print(json.dumps({
            "success": False,
            "message": "Usage: python reachability.py <config_file>"
        }))

        sys.exit(1)


    file_path = sys.argv[1]

    result = analyze_reachability(file_path)

    print(
        json.dumps(
            result,
            indent=2
        )
    )