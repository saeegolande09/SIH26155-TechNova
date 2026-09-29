import sys
import json
import os

from rules.telnet import check_telnet
from rules.ssh import check_ssh
from rules.encryption import check_encryption
from rules.access_rules import check_access_rules
from rules.authentication import check_authentication


def analyze_config(file_path, vendor):

    if not os.path.exists(file_path):

        return {
            "success": False,
            "message": "Configuration file not found"
        }

    # =========================
    # READ CONFIGURATION
    # =========================

    with open(
        file_path,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as file:

        config = file.read()

    findings = []

    # =========================
    # RUN SECURITY RULES
    # =========================

    findings.extend(
        check_telnet(config, vendor)
    )

    findings.extend(
        check_ssh(config, vendor)
    )

    findings.extend(
        check_encryption(config, vendor)
    )

    findings.extend(
        check_access_rules(config, vendor)
    )

    findings.extend(
        check_authentication(config, vendor)
    )

    # =========================
    # RULE STATUS
    # =========================

    rule_status = {
        "Remote Access": "PASS",
        "Encryption": "PASS",
        "Access Control": "PASS",
        "Authentication": "PASS"
    }

    for finding in findings:

        category = finding.get("category")
        severity = finding.get("severity")

        if category in rule_status:

            if severity in [
                "Critical",
                "High",
                "Medium"
            ]:
                rule_status[category] = "FAIL"

    # =========================
    # SCORE CALCULATION
    # =========================

    rule_weights = {
        "Remote Access": 25,
        "Encryption": 25,
        "Access Control": 25,
        "Authentication": 25
    }

    total_checks = len(rule_weights)

    passed_checks = 0
    failed_checks = 0

    compliance_score = 0

    for rule, weight in rule_weights.items():

        if rule_status[rule] == "PASS":

            passed_checks += 1
            compliance_score += weight

        else:

            failed_checks += 1

    # =========================
    # FINDING SEVERITY COUNTS
    # =========================

    critical_findings = 0
    high_findings = 0
    medium_findings = 0
    low_findings = 0

    for finding in findings:

        severity = finding.get("severity")

        if severity == "Critical":
            critical_findings += 1

        elif severity == "High":
            high_findings += 1

        elif severity == "Medium":
            medium_findings += 1

        elif severity == "Low":
            low_findings += 1

    # =========================
    # RESULT
    # =========================

    return {

        "success": True,

        "vendor": vendor,

        "totalChecks":
            total_checks,

        "passedChecks":
            passed_checks,

        "failedChecks":
            failed_checks,

        "complianceScore":
            compliance_score,

        "ruleStatus":
            rule_status,

        "criticalFindings":
            critical_findings,

        "highFindings":
            high_findings,

        "mediumFindings":
            medium_findings,

        "lowFindings":
            low_findings,

        "findings":
            findings
    }


# =========================
# MAIN
# =========================

if __name__ == "__main__":

    if len(sys.argv) < 3:

        print(
            json.dumps({
                "success": False,
                "message":
                    "Usage: python main.py <file_path> <vendor>"
            })
        )

        sys.exit(1)

    file_path = sys.argv[1]

    vendor = sys.argv[2]

    result = analyze_config(
        file_path,
        vendor
    )

    print(
        json.dumps(result)
    )