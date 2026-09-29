import sys
import json
import os
import re

from rules.telnet import check_telnet
from rules.ssh import check_ssh
from rules.encryption import check_encryption
from rules.access_rules import check_access_rules
from rules.authentication import check_authentication


# =========================================================
# FORTINET ADMINISTRATIVE PASSWORD CHECK
# =========================================================

def is_strong_password(password):

    if not password:
        return False

    password = str(password)

    # Minimum 10 characters
    if len(password) < 10:
        return False

    # Lowercase
    if not re.search(r"[a-z]", password):
        return False

    # Uppercase
    if not re.search(r"[A-Z]", password):
        return False

    # Number
    if not re.search(r"[0-9]", password):
        return False

    # Special character
    if not re.search(r"[^a-zA-Z0-9]", password):
        return False

    return True


def fortinet_password_is_secure(config):

    password_pattern = re.compile(
        r'set\s+password\s+(?:"([^"]*)"|(\S+))',
        re.IGNORECASE
    )

    matches = password_pattern.findall(config)

    # If there is no password line,
    # this function does not create a finding.
    if not matches:
        return True

    for match in matches:

        quoted_password = match[0]
        unquoted_password = match[1]

        if quoted_password:
            password = quoted_password
        else:
            password = unquoted_password

        if not is_strong_password(password):
            return False

    return True


def remove_secure_admin_password_finding(
    findings,
    config,
    vendor
):

    if str(vendor).lower() != "fortinet":
        return findings

    # Check whether the configured password is actually weak.
    password_is_secure = fortinet_password_is_secure(config)

    # If password is not secure, keep the finding.
    if not password_is_secure:
        return findings

    filtered_findings = []

    for finding in findings:

        title = str(
            finding.get("title", "")
        ).strip().lower()

        # Remove the finding when password is strong.
        if title == "administrative password configuration detected":
            continue

        filtered_findings.append(finding)

    return filtered_findings


# =========================================================
# ANALYZE CONFIGURATION
# =========================================================

def analyze_config(file_path, vendor):

    if not os.path.exists(file_path):

        return {
            "success": False,
            "message": "Configuration file not found"
        }

    # =====================================================
    # READ CONFIGURATION
    # =====================================================

    with open(
        file_path,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as file:

        config = file.read()

    findings = []

    # =====================================================
    # RUN SECURITY RULES
    # =====================================================

    findings.extend(
        check_telnet(
            config,
            vendor
        )
    )

    findings.extend(
        check_ssh(
            config,
            vendor
        )
    )

    findings.extend(
        check_encryption(
            config,
            vendor
        )
    )

    findings.extend(
        check_access_rules(
            config,
            vendor
        )
    )

    findings.extend(
        check_authentication(
            config,
            vendor
        )
    )

    # =====================================================
    # REMOVE FALSE POSITIVE ADMIN PASSWORD FINDING
    # =====================================================

    findings = remove_secure_admin_password_finding(
        findings,
        config,
        vendor
    )

    # =====================================================
    # RULE STATUS
    # =====================================================

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

    # =====================================================
    # SCORE CALCULATION
    # =====================================================

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

    # =====================================================
    # FINDING SEVERITY COUNTS
    # =====================================================

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

    # =====================================================
    # RESULT
    # =====================================================

    return {
        "success": True,

        "vendor": vendor,

        "totalChecks": total_checks,

        "passedChecks": passed_checks,

        "failedChecks": failed_checks,

        "complianceScore": compliance_score,

        "ruleStatus": rule_status,

        "criticalFindings": critical_findings,

        "highFindings": high_findings,

        "mediumFindings": medium_findings,

        "lowFindings": low_findings,

        "findings": findings
    }


# =========================================================
# MAIN
# =========================================================

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