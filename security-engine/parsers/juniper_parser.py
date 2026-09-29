import sys
import json
import os


def parse_juniper_config(file_path):

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

    hostname = None
    interfaces = []
    security_policies = []
    services = []
    authentication = []

    for line in lines:

        stripped = line.strip()

        if not stripped:
            continue

        lower_line = stripped.lower()


        # ======================================
        # HOSTNAME
        # ======================================

        if lower_line.startswith("set system host-name "):

            hostname = stripped.split(
                None,
                3
            )[3]


        # ======================================
        # INTERFACES
        # ======================================

        if lower_line.startswith("set interfaces "):

            parts = stripped.split()

            if len(parts) >= 3:

                interface_name = parts[2]

                existing_interface = next(
                    (
                        item
                        for item in interfaces
                        if item["name"] == interface_name
                    ),
                    None
                )

                if not existing_interface:

                    existing_interface = {
                        "name": interface_name,
                        "configuration": []
                    }

                    interfaces.append(
                        existing_interface
                    )

                existing_interface[
                    "configuration"
                ].append(stripped)


        # ======================================
        # SECURITY POLICIES
        # ======================================

        if (
            lower_line.startswith("set security policies ")
            or
            lower_line.startswith("set firewall ")
        ):

            security_policies.append(
                stripped
            )


        # ======================================
        # SSH
        # ======================================

        if (
            "set system services ssh" in lower_line
            or
            "set system services ssh " in lower_line
        ):

            services.append({
                "service": "SSH",
                "status": "Enabled"
            })


        # ======================================
        # TELNET
        # ======================================

        if "set system services telnet" in lower_line:

            services.append({
                "service": "Telnet",
                "status": "Enabled"
            })


        # ======================================
        # HTTP
        # ======================================

        if (
            "set system services web-management" in lower_line
        ):

            services.append({
                "service": "HTTP",
                "status": "Enabled"
            })


        # ======================================
        # ROOT AUTHENTICATION
        # ======================================

        if (
            "set system root-authentication" in lower_line
        ):

            authentication.append({
                "type": "Root Authentication",
                "configuration": stripped
            })


        # ======================================
        # USER AUTHENTICATION
        # ======================================

        if "set system login user " in lower_line:

            authentication.append({
                "type": "Local User",
                "configuration": stripped
            })


    return {
        "success": True,
        "vendor": "Juniper",
        "hostname": hostname,
        "interfaces": interfaces,
        "securityPolicies": security_policies,
        "services": services,
        "authentication": authentication
    }


if __name__ == "__main__":

    if len(sys.argv) < 2:

        print(json.dumps({
            "success": False,
            "message": "Usage: python juniper_parser.py <config_file>"
        }))

        sys.exit(1)


    file_path = sys.argv[1]

    result = parse_juniper_config(file_path)

    print(
        json.dumps(
            result,
            indent=2
        )
    )