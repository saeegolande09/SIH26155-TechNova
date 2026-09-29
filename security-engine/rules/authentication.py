def check_authentication(config, vendor):

    findings = []

    lines = config.splitlines()

    for line in lines:

        clean_line = line.strip().lower()

        # =========================
        # CISCO
        # =========================

        if vendor == "Cisco":

            # Plaintext enable password
            if "enable password" in clean_line:

                findings.append({
                    "title": "Plaintext Enable Password",
                    "category": "Authentication",
                    "severity": "High",
                    "description":
                        "A plaintext enable password was detected in the Cisco configuration.",
                    "detectedConfig":
                        line.strip(),
                    "recommendedFix":
                        "Replace the plaintext password with an encrypted secret using 'enable secret' and protect configuration access."
                })

            # Weak local password
            elif (
                "username " in clean_line
                and " password " in clean_line
                and "secret" not in clean_line
            ):

                findings.append({
                    "title": "Plaintext Local User Password",
                    "category": "Authentication",
                    "severity": "High",
                    "description":
                        "A local user account appears to use a plaintext password.",
                    "detectedConfig":
                        line.strip(),
                    "recommendedFix":
                        "Use a secure secret-based credential instead of a plaintext password."
                })


        # =========================
        # JUNIPER
        # =========================

        elif vendor == "Juniper":

            if (
                "encrypted-password" not in clean_line
                and "plain-text-password" in clean_line
            ):

                findings.append({
                    "title": "Plaintext Password Detected",
                    "category": "Authentication",
                    "severity": "High",
                    "description":
                        "A plaintext password configuration was detected in the Juniper configuration.",
                    "detectedConfig":
                        line.strip(),
                    "recommendedFix":
                        "Use encrypted password storage and secure authentication mechanisms."
                })


        # =========================
        # FORTINET
        # =========================

        elif vendor == "Fortinet":

            if (
                "set password " in clean_line
                and "password-expire" not in clean_line
            ):

                findings.append({
                    "title": "Administrative Password Configuration Detected",
                    "category": "Authentication",
                    "severity": "Medium",
                    "description":
                        "A Fortinet administrative password configuration was detected.",
                    "detectedConfig":
                        line.strip(),
                    "recommendedFix":
                        "Use strong administrative credentials and ensure configuration files are properly protected."
                })

    return findings