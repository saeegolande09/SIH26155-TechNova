function analyzeUnknownConfiguration(configLine, vendor) {

    if (!configLine || !configLine.trim()) {
        return {
            success: false,
            message: "Configuration line is required."
        };
    }

    const config = configLine.trim();
    const lowerConfig = config.toLowerCase();

    let category = "Unknown";
    let possibleMeaning = "";
    let riskLevel = "Low";
    let suggestedAction = "";
    let confidence = 50;

    // ===============================
    // AUTHENTICATION
    // ===============================

    if (
        lowerConfig.includes("password") ||
        lowerConfig.includes("authentication") ||
        lowerConfig.includes("login") ||
        lowerConfig.includes("credential")
    ) {

        category = "Authentication";

        possibleMeaning =
            "This configuration appears to be related to user authentication or credential management.";

        riskLevel = "Medium";

        suggestedAction =
            "Review the authentication method and ensure that credentials are securely stored and strong authentication is enforced.";

        confidence = 88;
    }


    // ===============================
    // REMOTE ACCESS
    // ===============================

    else if (
        lowerConfig.includes("telnet") ||
        lowerConfig.includes("ssh") ||
        lowerConfig.includes("remote")
    ) {

        category = "Remote Access";

        possibleMeaning =
            "This configuration appears to control remote administrative access to the network device.";

        if (lowerConfig.includes("telnet")) {

            riskLevel = "High";

            suggestedAction =
                "Disable Telnet and use SSH for secure remote administration.";

        } else {

            riskLevel = "Low";

            suggestedAction =
                "Review SSH configuration and ensure secure authentication and restricted management access.";

        }

        confidence = 92;
    }


    // ===============================
    // ACCESS CONTROL
    // ===============================

    else if (
        lowerConfig.includes("permit") ||
        lowerConfig.includes("deny") ||
        lowerConfig.includes("acl") ||
        lowerConfig.includes("policy") ||
        lowerConfig.includes("firewall")
    ) {

        category = "Access Control";

        possibleMeaning =
            "This configuration appears to define network traffic access or security policy rules.";

        riskLevel = "Medium";

        suggestedAction =
            "Review the rule for overly permissive access and ensure that only required traffic is allowed.";

        confidence = 86;
    }


    // ===============================
    // ENCRYPTION
    // ===============================

    else if (
        lowerConfig.includes("encrypt") ||
        lowerConfig.includes("encryption") ||
        lowerConfig.includes("cipher") ||
        lowerConfig.includes("ssl") ||
        lowerConfig.includes("tls")
    ) {

        category = "Encryption";

        possibleMeaning =
            "This configuration appears to control encryption or secure communication settings.";

        riskLevel = "Medium";

        suggestedAction =
            "Verify that strong encryption protocols and secure cryptographic algorithms are being used.";

        confidence = 84;
    }


    // ===============================
    // NETWORK SERVICE
    // ===============================

    else if (
        lowerConfig.includes("http") ||
        lowerConfig.includes("ftp") ||
        lowerConfig.includes("snmp") ||
        lowerConfig.includes("service")
    ) {

        category = "Network Service";

        possibleMeaning =
            "This configuration appears to enable or configure a network service.";

        riskLevel = "Medium";

        suggestedAction =
            "Verify that the service is required and restrict access to trusted sources.";

        confidence = 80;
    }


    // ===============================
    // UNKNOWN
    // ===============================

    else {

        category = "Unknown";

        possibleMeaning =
            "The configuration could not be confidently mapped to a known security category.";

        riskLevel = "Low";

        suggestedAction =
            "Review this configuration manually and consider adding a dedicated security rule if required.";

        confidence = 40;
    }


    return {

        success: true,

        vendor: vendor || "Unknown",

        originalConfiguration: config,

        category,

        possibleMeaning,

        riskLevel,

        confidence,

        suggestedAction

    };
}


module.exports = {
    analyzeUnknownConfiguration
};