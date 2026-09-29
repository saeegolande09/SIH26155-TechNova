def check_access_rules(config, vendor):

    findings = []

    lines = config.splitlines()

    for line in lines:

        clean_line = line.strip().lower()

        # =========================
        # CISCO
        # =========================

        if vendor == "Cisco":

            # =========================
            # TELNET
            # =========================

            if (
                "permit tcp any any eq 23" in clean_line
                or "permit tcp any any eq telnet" in clean_line
            ):

                findings.append({
                    "title": "Telnet Traffic Permitted",
                    "category": "Access Control",
                    "severity": "High",
                    "description":
                        "An ACL permits Telnet traffic from any source to any destination.",
                    "detectedConfig":
                        line.strip(),
                    "recommendedFix":
                        "Block Telnet traffic and use SSH for secure remote administration."
                })

            # =========================
            # HTTP
            # =========================

            elif (
                "permit tcp any any eq 80" in clean_line
                or "permit tcp any any eq www" in clean_line
            ):

                findings.append({
                    "title": "HTTP Traffic Exposed",
                    "category": "Access Control",
                    "severity": "Medium",
                    "description":
                        "An ACL permits HTTP traffic from any source to any destination.",
                    "detectedConfig":
                        line.strip(),
                    "recommendedFix":
                        "Restrict HTTP access or use HTTPS where applicable."
                })

            # =========================
            # ANY-TO-ANY
            # =========================

            elif (
                "permit ip any any" in clean_line
                or "permit tcp any any" in clean_line
                or "permit udp any any" in clean_line
            ):

                findings.append({
                    "title": "Overly Permissive Access Rule",
                    "category": "Access Control",
                    "severity": "High",
                    "description":
                        "An access control rule allows traffic from any source "
                        "to any destination. This can unnecessarily expose network resources.",
                    "detectedConfig":
                        line.strip(),
                    "recommendedFix":
                        "Restrict the source, destination, protocol, and ports "
                        "to only what is required."
                })

        # =========================
        # JUNIPER
        # =========================

        elif vendor == "Juniper":

            if (
                "source-address any" in clean_line
                or "destination-address any" in clean_line
            ):

                findings.append({
                    "title": "Broad Security Policy",
                    "category": "Access Control",
                    "severity": "Medium",
                    "description":
                        "A Juniper security policy uses a broad any source or destination.",
                    "detectedConfig":
                        line.strip(),
                    "recommendedFix":
                        "Restrict source and destination addresses to the required networks."
                })

        # =========================
        # FORTINET
        # =========================

        elif vendor == "Fortinet":

            if (
                'set srcaddr "all"' in clean_line
                or 'set dstaddr "all"' in clean_line
            ):

                findings.append({
                    "title": "Broad Firewall Policy",
                    "category": "Access Control",
                    "severity": "Medium",
                    "description":
                        "A Fortinet firewall policy allows a broad source or destination.",
                    "detectedConfig":
                        line.strip(),
                    "recommendedFix":
                        "Restrict source and destination objects to only the required networks."
                })

            elif 'set service "all"' in clean_line:

                findings.append({
                    "title": "All Services Permitted",
                    "category": "Access Control",
                    "severity": "High",
                    "description":
                        "A Fortinet firewall policy permits all services.",
                    "detectedConfig":
                        line.strip(),
                    "recommendedFix":
                        "Restrict the policy to only the required services and ports."
                })

    return findings