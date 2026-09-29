function generateAIExplanation(finding) {

    if (!finding) {
        return {
            success: false,
            message: "Finding data is required."
        };
    }

    const title = finding.title || "Security Finding";
    const severity = finding.severity || "Unknown";
    const category = finding.category || "Other";
    const detectedConfig = finding.detectedConfig || "";
    const recommendedFix =
        finding.recommendedFix || "Review the configuration manually.";

    let explanation = "";
    let aiRecommendedFix = recommendedFix;

    const lowerTitle = title.toLowerCase();
    const lowerConfig = detectedConfig.toLowerCase();

    // TELNET
    if (
        lowerTitle.includes("telnet") ||
        lowerConfig.includes("telnet")
    ) {
        explanation =
            "Telnet transmits remote-access communication without the security protections provided by SSH. " +
            "If exposed to an untrusted network, credentials and session data may be intercepted. " +
            "This configuration should be reviewed and secure remote administration should be preferred.";

        aiRecommendedFix =
            "Disable Telnet and use SSH for secure remote administration. " +
            "Restrict SSH access to trusted management networks and use strong authentication.";
    }

    // PLAINTEXT PASSWORD
    else if (
        lowerTitle.includes("password") ||
        lowerConfig.includes("enable password")
    ) {
        explanation =
            "A plaintext password configuration was detected. " +
            "Plaintext credentials can expose administrative access if the configuration file is accessed by an unauthorized person.";

        aiRecommendedFix =
            "Replace the plaintext password with a secure hashed or secret-based credential. " +
            "Restrict access to configuration files and use strong authentication.";
    }

    // SSH
    else if (lowerTitle.includes("ssh")) {
        explanation =
            "SSH provides encrypted remote administration. " +
            "The configuration should still be reviewed to ensure strong authentication, secure cryptographic settings, and restricted administrative access.";

        aiRecommendedFix =
            "Use SSH with strong authentication and secure cryptographic settings. " +
            "Restrict SSH access to trusted management networks.";
    }

    // DEFAULT
    else {
        explanation =
            `The security engine detected a ${severity} severity finding in the ${category} category. ` +
            "The detected configuration should be reviewed to determine whether it creates a security or compliance risk.";

        aiRecommendedFix = recommendedFix;
    }

    return {
        success: true,
        title: title,
        severity: severity,
        category: category,
        explanation: explanation,
        recommendedFix: aiRecommendedFix,
        detectedConfig: detectedConfig
    };
}

module.exports = {
    generateAIExplanation
};