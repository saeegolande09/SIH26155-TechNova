def check_ssh(config, vendor):

    findings = []

    lines = config.splitlines()

    for line in lines:

        clean_line = line.strip().lower()

        # =========================
        # CISCO
        # =========================

        if vendor == "Cisco":

            if "transport input ssh" in clean_line:

                findings.append({
                    "title": "SSH Enabled",
                    "category": "Remote Access",
                    "severity": "Low",
                    "description":
                        "SSH is enabled for remote administration. "
                        "SSH provides encrypted communication and is preferred "
                        "over insecure remote-access protocols such as Telnet.",
                    "detectedConfig": line.strip(),
                    "recommendedFix":
                        "Keep SSH enabled and restrict SSH access to trusted management networks."
                })


        # =========================
        # JUNIPER
        # =========================

        elif vendor == "Juniper":

            if clean_line == "set system services ssh":

                findings.append({
                    "title": "SSH Enabled",
                    "category": "Remote Access",
                    "severity": "Low",
                    "description":
                        "Juniper SSH service is enabled for secure remote administration.",
                    "detectedConfig": line.strip(),
                    "recommendedFix":
                        "Keep SSH enabled and restrict management access to trusted networks."
                })


        # =========================
        # FORTINET
        # =========================

        elif vendor == "Fortinet":

            if (
                "set allowaccess" in clean_line
                and "ssh" in clean_line
            ):

                findings.append({
                    "title": "SSH Management Access Enabled",
                    "category": "Remote Access",
                    "severity": "Low",
                    "description":
                        "SSH management access is enabled on a Fortinet interface.",
                    "detectedConfig": line.strip(),
                    "recommendedFix":
                        "Keep SSH enabled only where required and restrict management access to trusted networks."
                })


    return findings