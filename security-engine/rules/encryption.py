def check_encryption(config, vendor):

    findings = []

    lines = config.splitlines()

    for line in lines:

        clean_line = line.strip().lower()

        # =========================
        # CISCO
        # =========================

        if vendor == "Cisco":

            if "crypto isakmp policy" in clean_line:
                continue

            if (
                "encryption des" in clean_line
                or "encryption 3des" in clean_line
            ):

                findings.append({
                    "title": "Weak Encryption Detected",
                    "category": "Encryption",
                    "severity": "High",
                    "description":
                        "A weak or outdated encryption algorithm was detected "
                        "in the Cisco configuration.",
                    "detectedConfig":
                        line.strip(),
                    "recommendedFix":
                        "Replace weak encryption algorithms with modern "
                        "strong encryption such as AES."
                })


        # =========================
        # JUNIPER
        # =========================

        elif vendor == "Juniper":

            if (
                "3des" in clean_line
                or "des " in clean_line
                or "des;" in clean_line
            ):

                findings.append({
                    "title": "Weak Encryption Detected",
                    "category": "Encryption",
                    "severity": "High",
                    "description":
                        "A weak or outdated encryption algorithm was detected "
                        "in the Juniper configuration.",
                    "detectedConfig":
                        line.strip(),
                    "recommendedFix":
                        "Use modern encryption algorithms such as AES."
                })


        # =========================
        # FORTINET
        # =========================

        elif vendor == "Fortinet":

            if (
                "3des" in clean_line
                or "des" in clean_line
            ):

                findings.append({
                    "title": "Weak Encryption Detected",
                    "category": "Encryption",
                    "severity": "High",
                    "description":
                        "A weak or outdated encryption algorithm was detected "
                        "in the Fortinet configuration.",
                    "detectedConfig":
                        line.strip(),
                    "recommendedFix":
                        "Replace weak encryption with modern strong encryption "
                        "such as AES."
                })


    return findings