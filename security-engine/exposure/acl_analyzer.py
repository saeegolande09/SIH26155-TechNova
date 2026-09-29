import sys
import json
import os


def analyze_acl(file_path):

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

    permits = []
    denies = []

    for line in lines:

        line = line.strip()

        if not line:
            continue

        lower_line = line.lower()

        if "permit" in lower_line:
            permits.append(line)

        if "deny" in lower_line:
            denies.append(line)


    # Detect exposed services
    exposed_services = []

    config_lower = config.lower()

    # Direct service detection
    if "telnet" in config_lower:
        exposed_services.append("Telnet")

    if "http" in config_lower:
        exposed_services.append("HTTP")

    if "ftp" in config_lower:
        exposed_services.append("FTP")

    if "snmp" in config_lower:
        exposed_services.append("SNMP")


    # Port-based service detection
    for line in permits:

        lower_line = line.lower()

        if "eq 23" in lower_line:
            if "Telnet" not in exposed_services:
                exposed_services.append("Telnet")

        if "eq 80" in lower_line:
            if "HTTP" not in exposed_services:
                exposed_services.append("HTTP")

        if "eq 21" in lower_line:
            if "FTP" not in exposed_services:
                exposed_services.append("FTP")

        if "eq 161" in lower_line:
            if "SNMP" not in exposed_services:
                exposed_services.append("SNMP")


    # Risk calculation
    risk_level = "Low"

    if exposed_services:
        risk_level = "High"

    elif len(permits) > 5:
        risk_level = "Medium"


    return {
        "success": True,
        "totalPermitRules": len(permits),
        "totalDenyRules": len(denies),
        "exposedServices": exposed_services,
        "permitRules": permits,
        "denyRules": denies,
        "riskLevel": risk_level
    }


if __name__ == "__main__":

    if len(sys.argv) < 2:

        print(json.dumps({
            "success": False,
            "message": "Usage: python acl_analyzer.py <config_file>"
        }))

        sys.exit(1)


    file_path = sys.argv[1]

    result = analyze_acl(file_path)

    print(
        json.dumps(
            result,
            indent=2
        )
    )