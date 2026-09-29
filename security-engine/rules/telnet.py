import re


def check_telnet(config, vendor):

    findings = []

    lines = config.splitlines()

    for line in lines:

        clean_line = line.strip().lower()

        # =========================
        # CISCO
        # =========================

        if vendor == "Cisco":

            if (
                "transport input telnet" in clean_line
                or "transport input telnet ssh" in clean_line
                or "transport input ssh telnet" in clean_line
            ):

                findings.append({
                    "title": "Telnet Enabled",
                    "category": "Remote Access",
                    "severity": "High",
                    "description":
                        "Telnet is enabled for remote administration. "
                        "Telnet does not provide encrypted communication "
                        "and may expose credentials and session data.",
                    "detectedConfig": line.strip(),
                    "recommendedFix":
                        "Disable Telnet and use SSH for secure remote administration."
                })


        # =========================
        # JUNIPER
        # =========================

        elif vendor == "Juniper":

            if clean_line == "set system services telnet":

                findings.append({
                    "title": "Telnet Enabled",
                    "category": "Remote Access",
                    "severity": "High",
                    "description":
                        "Juniper Telnet service is enabled. "
                        "Telnet provides insecure remote administration "
                        "without encrypted communication.",
                    "detectedConfig": line.strip(),
                    "recommendedFix":
                        "Disable Telnet and use SSH for secure remote administration."
                })


        # =========================
        # FORTINET
        # =========================

        elif vendor == "Fortinet":

            if (
                "set allowaccess" in clean_line
                and re.search(r"\btelnet\b", clean_line)
            ):

                findings.append({
                    "title": "Telnet Access Enabled",
                    "category": "Remote Access",
                    "severity": "High",
                    "description":
                        "Telnet management access is enabled on a Fortinet interface. "
                        "This can expose administrative communication to interception.",
                    "detectedConfig": line.strip(),
                    "recommendedFix":
                        "Remove Telnet from interface management access and use SSH instead."
                })


    return findings