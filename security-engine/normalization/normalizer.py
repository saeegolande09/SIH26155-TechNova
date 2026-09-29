import sys
import json
import os


def normalize_config(parsed_data):

    if not parsed_data.get("success"):
        return {
            "success": False,
            "message": "Invalid parser output"
        }

    vendor = parsed_data.get(
        "vendor",
        "Unknown"
    )

    normalized = {
        "success": True,
        "vendor": vendor,
        "hostname": parsed_data.get("hostname"),
        "interfaces": [],
        "services": [],
        "securityRules": [],
        "authentication": []
    }


    # ==========================================
    # NORMALIZE INTERFACES
    # ==========================================

    for interface in parsed_data.get(
        "interfaces",
        []
    ):

        normalized["interfaces"].append({

            "name": interface.get(
                "name"
            ),

            "configuration":
                interface.get(
                    "configuration",
                    []
                )

        })


    # ==========================================
    # NORMALIZE SERVICES
    # ==========================================

    for service in parsed_data.get(
        "services",
        []
    ):

        normalized["services"].append({

            "service":
                service.get(
                    "service"
                ),

            "status":
                service.get(
                    "status"
                )

        })


    # ==========================================
    # NORMALIZE AUTHENTICATION
    # ==========================================

    for auth in parsed_data.get(
        "authentication",
        []
    ):

        normalized["authentication"].append({

            "type":
                auth.get(
                    "type"
                ),

            "security":
                auth.get(
                    "security",
                    None
                ),

            "configuration":
                auth.get(
                    "configuration",
                    None
                )

        })


    # ==========================================
    # CISCO SECURITY RULES
    # ==========================================

    if vendor == "Cisco":

        for rule in parsed_data.get(
            "accessLists",
            []
        ):

            normalized["securityRules"].append({

                "type": "ACL",

                "configuration": rule

            })


    # ==========================================
    # JUNIPER SECURITY RULES
    # ==========================================

    elif vendor == "Juniper":

        for rule in parsed_data.get(
            "securityPolicies",
            []
        ):

            normalized["securityRules"].append({

                "type": "Security Policy",

                "configuration": rule

            })


    # ==========================================
    # FORTINET SECURITY RULES
    # ==========================================

    elif vendor == "Fortinet":

        for policy in parsed_data.get(
            "firewallPolicies",
            []
        ):

            normalized["securityRules"].append({

                "type": "Firewall Policy",

                "id": policy.get(
                    "id"
                ),

                "configuration":
                    policy.get(
                        "configuration",
                        []
                    )

            })


    return normalized


# ==========================================
# MAIN
# ==========================================

if __name__ == "__main__":

    if len(sys.argv) < 2:

        print(
            json.dumps({

                "success": False,

                "message":
                    "Usage: python normalizer.py <parser_output.json>"

            })
        )

        sys.exit(1)


    input_file = sys.argv[1]


    # ======================================
    # CHECK FILE
    # ======================================

    if not os.path.exists(input_file):

        print(
            json.dumps({

                "success": False,

                "message":
                    "Parser output file not found"

            })
        )

        sys.exit(1)


    # ======================================
    # READ JSON
    # ======================================

    try:

        with open(
            input_file,
            "r",
            encoding="utf-8-sig"
        ) as file:

            parsed_data = json.load(file)

    except json.JSONDecodeError as error:

        print(
            json.dumps({

                "success": False,

                "message":
                    "Invalid JSON file",

                "error":
                    str(error)

            })
        )

        sys.exit(1)


    # ======================================
    # NORMALIZE
    # ======================================

    result = normalize_config(
        parsed_data
    )


    # ======================================
    # OUTPUT
    # ======================================

    print(
        json.dumps(
            result,
            indent=2
        )
    )