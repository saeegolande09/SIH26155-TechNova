import sys
import json
import os
import re


def analyze_attack_surface(file_path):

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

    exposed_services = []
    reachable_rules = []

    permit_count = 0
    deny_count = 0

    # ==========================================
    # HELPER
    # ==========================================

    def add_service(service):
        if service not in exposed_services:
            exposed_services.append(service)

    # ==========================================
    # CISCO / JUNIPER ACL RULES
    # ==========================================

    for line in lines:

        original_line = line.strip()

        if not original_line:
            continue

        lower_line = original_line.lower()

        # ------------------------------
        # DENY
        # ------------------------------

        if lower_line.startswith("deny "):
            deny_count += 1

        # ------------------------------
        # PERMIT
        # ------------------------------

        if lower_line.startswith("permit "):

            permit_count += 1

            parts = lower_line.split()

            source = "Unknown"
            destination = "Unknown"
            protocol = "Unknown"
            port = None

            try:

                permit_index = parts.index("permit")

                protocol_index = permit_index + 1

                if protocol_index < len(parts):
                    protocol = parts[protocol_index].upper()

                source_index = protocol_index + 1
                destination_index = protocol_index + 2

                if source_index < len(parts):
                    source = parts[source_index]

                if destination_index < len(parts):
                    destination = parts[destination_index]

            except (ValueError, IndexError):
                pass

            # --------------------------
            # PORT
            # --------------------------

            port_match = re.search(
                r"eq\s+(\d+)",
                lower_line
            )

            if port_match:
                port = int(port_match.group(1))

            # --------------------------
            # SERVICES
            # --------------------------

            if port == 23 or "telnet" in lower_line:
                add_service("Telnet")

            if port == 80 or "http" in lower_line:
                add_service("HTTP")

            if port == 443 or "https" in lower_line:
                add_service("HTTPS")

            if port == 21 or "ftp" in lower_line:
                add_service("FTP")

            if port == 22 or "ssh" in lower_line:
                add_service("SSH")

            if port == 161 or "snmp" in lower_line:
                add_service("SNMP")

            # --------------------------
            # REACHABLE RULE
            # --------------------------

            reachable_rules.append({
                "rule": original_line,
                "source": source,
                "destination": destination,
                "protocol": protocol,
                "port": port
            })

    # ==========================================
    # FORTINET FIREWALL POLICY PARSER
    # ==========================================

    in_firewall_policy = False

    current_srcaddr = "Unknown"
    current_dstaddr = "Unknown"
    current_service = "Unknown"
    current_action = "Unknown"

    def process_fortinet_policy():

        nonlocal permit_count
        nonlocal deny_count

        if not in_firewall_policy:
            return

        action = current_action.lower()

        # ------------------------------
        # ACCEPT
        # ------------------------------

        if action == "accept":

            permit_count += 1

            service = current_service.lower()

            if "telnet" in service:
                add_service("Telnet")

            if "http" in service:
                add_service("HTTP")

            if "https" in service:
                add_service("HTTPS")

            if "ftp" in service:
                add_service("FTP")

            if "ssh" in service:
                add_service("SSH")

            if "snmp" in service:
                add_service("SNMP")

            if service == "all":
                add_service("All Services")

            reachable_rules.append({
                "rule": "Fortinet Firewall Policy",
                "source": current_srcaddr,
                "destination": current_dstaddr,
                "protocol": "ALL",
                "port": None
            })

        # ------------------------------
        # DENY / REJECT
        # ------------------------------

        elif action in ["deny", "reject"]:

            deny_count += 1

    # ==========================================
    # READ FORTINET CONFIG
    # ==========================================

    for line in lines:

        original_line = line.strip()
        lower_line = original_line.lower()

        # Start of firewall policy
        if lower_line.startswith("edit "):

            # Process previous policy
            if in_firewall_policy:
                process_fortinet_policy()

            # Start new block
            in_firewall_policy = True

            current_srcaddr = "Unknown"
            current_dstaddr = "Unknown"
            current_service = "Unknown"
            current_action = "Unknown"

            continue

        if not in_firewall_policy:
            continue

        # ------------------------------
        # SOURCE ADDRESS
        # ------------------------------

        if lower_line.startswith("set srcaddr "):

            current_srcaddr = original_line[
                len("set srcaddr "):
            ].strip()

        # ------------------------------
        # DESTINATION ADDRESS
        # ------------------------------

        elif lower_line.startswith("set dstaddr "):

            current_dstaddr = original_line[
                len("set dstaddr "):
            ].strip()

        # ------------------------------
        # SERVICE
        # ------------------------------

        elif lower_line.startswith("set service "):

            current_service = original_line[
                len("set service "):
            ].strip()

        # ------------------------------
        # ACTION
        # ------------------------------

        elif lower_line.startswith("set action "):

            current_action = original_line[
                len("set action "):
            ].strip()

        # ------------------------------
        # END POLICY
        # ------------------------------

        elif lower_line == "next":

            process_fortinet_policy()

            in_firewall_policy = False

    # Process final policy
    if in_firewall_policy:
        process_fortinet_policy()

    # ==========================================
    # FORTINET MANAGEMENT ACCESS
    # ==========================================

    config_lower = config.lower()

    allowaccess_matches = re.findall(
        r"set allowaccess\s+(.+)",
        config_lower
    )

    for match in allowaccess_matches:

        if "telnet" in match:
            add_service("Telnet")

        if "http" in match:
            add_service("HTTP")

        if "https" in match:
            add_service("HTTPS")

        if "ssh" in match:
            add_service("SSH")

        if "snmp" in match:
            add_service("SNMP")

    # ==========================================
    # ATTACK SURFACE SCORE
    # ==========================================

    attack_surface_score = 0

    # Each exposed service
    attack_surface_score += (
        len(exposed_services) * 20
    )

    # Each reachable rule
    attack_surface_score += (
        len(reachable_rules) * 10
    )

    if attack_surface_score > 100:
        attack_surface_score = 100

    # ==========================================
    # ANY-ANY DETECTION
    # ==========================================

    any_any_rule = False

    for rule in reachable_rules:

        source = str(
            rule["source"]
        ).lower()

        destination = str(
            rule["destination"]
        ).lower()

        if (
            "any" in source
            and "any" in destination
        ):

            any_any_rule = True
            break

    # ==========================================
    # RISK LEVEL
    # ==========================================

    risk_level = "Low"

    if attack_surface_score >= 70:

        risk_level = "Critical"

    elif attack_surface_score >= 40:

        risk_level = "High"

    elif attack_surface_score >= 20:

        risk_level = "Medium"

    # Any-to-any increases risk
    if any_any_rule:

        if risk_level == "Low":
            risk_level = "Medium"

        elif risk_level == "Medium":
            risk_level = "High"

    # ==========================================
    # RESULT
    # ==========================================

    return {
        "success": True,
        "attackSurfaceScore": attack_surface_score,
        "riskLevel": risk_level,
        "exposedServices": exposed_services,
        "totalPermitRules": permit_count,
        "totalDenyRules": deny_count,
        "totalReachableRules": len(reachable_rules),
        "reachableRules": reachable_rules
    }


# ==========================================
# MAIN
# ==========================================

if __name__ == "__main__":

    if len(sys.argv) < 2:

        print(
            json.dumps({
                "success": False,
                "message":
                    "Usage: python attack_surface.py <config_file>"
            })
        )

        sys.exit(1)

    file_path = sys.argv[1]

    result = analyze_attack_surface(
        file_path
    )

    print(
        json.dumps(
            result,
            indent=2
        )
    )