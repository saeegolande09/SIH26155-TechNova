import sys
import json
import os
import re


def parse_cisco_config(file_path):

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
    access_lists = []
    services = []
    authentication = []

    current_interface = None

    for line in lines:

        stripped = line.strip()

        if not stripped:
            continue

        lower_line = stripped.lower()


        # ======================================
        # HOSTNAME
        # ======================================

        if lower_line.startswith("hostname "):

            hostname = stripped.split(
                None,
                1
            )[1]


        # ======================================
        # INTERFACE
        # ======================================

        if lower_line.startswith("interface "):

            current_interface = stripped.split(
                None,
                1
            )[1]

            interfaces.append({
                "name": current_interface,
                "configuration": []
            })

            continue


        # Interface configuration
        if current_interface:

            if line.startswith(" ") or line.startswith("\t"):

                interfaces[-1]["configuration"].append(
                    stripped
                )


        # ======================================
        # ACCESS LIST
        # ======================================

        if (
            lower_line.startswith("access-list ")
            or
            lower_line.startswith("ip access-list ")
        ):

            access_lists.append(stripped)


        # ======================================
        # TELNET
        # ======================================

        if "transport input telnet" in lower_line:

            services.append({
                "service": "Telnet",
                "status": "Enabled"
            })


        # ======================================
        # SSH
        # ======================================

        if "transport input ssh" in lower_line:

            services.append({
                "service": "SSH",
                "status": "Enabled"
            })


        # ======================================
        # HTTP
        # ======================================

        if (
            lower_line.startswith("ip http server")
            or
            lower_line.startswith("ip http secure-server")
        ):

            services.append({
                "service": "HTTP",
                "status": "Enabled"
            })


        # ======================================
        # ENABLE PASSWORD
        # ======================================

        if lower_line.startswith("enable password "):

            authentication.append({
                "type": "Enable Password",
                "security": "Plaintext"
            })


        # ======================================
        # ENABLE SECRET
        # ======================================

        if lower_line.startswith("enable secret "):

            authentication.append({
                "type": "Enable Secret",
                "security": "Hashed/Secret"
            })


        # ======================================
        # USERNAME
        # ======================================

        if lower_line.startswith("username "):

            authentication.append({
                "type": "Local User",
                "configuration": stripped
            })


    return {
        "success": True,
        "vendor": "Cisco",
        "hostname": hostname,
        "interfaces": interfaces,
        "accessLists": access_lists,
        "services": services,
        "authentication": authentication
    }


if __name__ == "__main__":

    if len(sys.argv) < 2:

        print(json.dumps({
            "success": False,
            "message": "Usage: python cisco_parser.py <config_file>"
        }))

        sys.exit(1)


    file_path = sys.argv[1]

    result = parse_cisco_config(file_path)

    print(
        json.dumps(
            result,
            indent=2
        )
    )