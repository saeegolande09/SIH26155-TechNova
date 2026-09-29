import sys
import json
import os


def parse_fortinet_config(file_path):

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
    firewall_policies = []
    services = []
    authentication = []

    current_section = None
    current_interface = None
    current_policy = None

    for line in lines:

        stripped = line.strip()

        if not stripped:
            continue

        lower_line = stripped.lower()


        # ======================================
        # HOSTNAME
        # ======================================

        if lower_line.startswith("set hostname "):

            hostname = stripped.split(
                None,
                2
            )[2]


        # ======================================
        # SYSTEM GLOBAL HOSTNAME
        # ======================================

        if lower_line.startswith("set hostname"):

            parts = stripped.split(None, 2)

            if len(parts) >= 3:
                hostname = parts[2]


        # ======================================
        # INTERFACE SECTION
        # ======================================

        if lower_line == "config system interface":

            current_section = "interface"
            current_interface = None
            continue


        if (
            current_section == "interface"
            and lower_line.startswith("edit ")
        ):

            interface_name = stripped[5:].strip()

            current_interface = {
                "name": interface_name,
                "configuration": []
            }

            interfaces.append(current_interface)
            continue


        if (
            current_section == "interface"
            and lower_line.startswith("set ")
            and current_interface
        ):

            current_interface["configuration"].append(
                stripped
            )


        # ======================================
        # FIREWALL POLICY SECTION
        # ======================================

        if lower_line == "config firewall policy":

            current_section = "firewall_policy"
            current_policy = None
            continue


        if (
            current_section == "firewall_policy"
            and lower_line.startswith("edit ")
        ):

            policy_id = stripped[5:].strip()

            current_policy = {
                "id": policy_id,
                "configuration": []
            }

            firewall_policies.append(
                current_policy
            )

            continue


        if (
            current_section == "firewall_policy"
            and lower_line.startswith("set ")
            and current_policy
        ):

            current_policy["configuration"].append(
                stripped
            )


        # ======================================
        # SSH
        # ======================================

        if (
            "set allowaccess" in lower_line
            and "ssh" in lower_line
        ):

            services.append({
                "service": "SSH",
                "status": "Enabled"
            })


        # ======================================
        # HTTP
        # ======================================

        if (
            "set allowaccess" in lower_line
            and "http" in lower_line
        ):

            services.append({
                "service": "HTTP",
                "status": "Enabled"
            })


        # ======================================
        # HTTPS
        # ======================================

        if (
            "set allowaccess" in lower_line
            and "https" in lower_line
        ):

            services.append({
                "service": "HTTPS",
                "status": "Enabled"
            })


        # ======================================
        # TELNET
        # ======================================

        if (
            "set allowaccess" in lower_line
            and "telnet" in lower_line
        ):

            services.append({
                "service": "Telnet",
                "status": "Enabled"
            })


        # ======================================
        # FTP
        # ======================================

        if (
            "set allowaccess" in lower_line
            and "ftp" in lower_line
        ):

            services.append({
                "service": "FTP",
                "status": "Enabled"
            })


        # ======================================
        # ADMIN USER
        # ======================================

        if lower_line.startswith("config system admin"):

            current_section = "admin"


        if (
            current_section == "admin"
            and lower_line.startswith("edit ")
        ):

            authentication.append({
                "type": "Admin User",
                "configuration": stripped
            })


        # ======================================
        # PASSWORD
        # ======================================

        if (
            current_section == "admin"
            and "set password" in lower_line
        ):

            authentication.append({
                "type": "Admin Password",
                "configuration": stripped
            })


    return {
        "success": True,
        "vendor": "Fortinet",
        "hostname": hostname,
        "interfaces": interfaces,
        "firewallPolicies": firewall_policies,
        "services": services,
        "authentication": authentication
    }


if __name__ == "__main__":

    if len(sys.argv) < 2:

        print(json.dumps({
            "success": False,
            "message": "Usage: python fortinet_parser.py <config_file>"
        }))

        sys.exit(1)


    file_path = sys.argv[1]

    result = parse_fortinet_config(file_path)

    print(
        json.dumps(
            result,
            indent=2
        )
    )