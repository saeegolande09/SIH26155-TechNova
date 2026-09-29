const fs = require("fs");

function detectVendor(filePath) {

    if (!fs.existsSync(filePath)) {
        return {
            success: false,
            vendor: "Unknown",
            message: "Configuration file not found"
        };
    }

    const config = fs.readFileSync(
        filePath,
        "utf8"
    );

    const lowerConfig = config.toLowerCase();

    let vendor = "Unknown";
    let confidence = 0;

    // -----------------------------
    // CISCO
    // -----------------------------

    if (
        lowerConfig.includes("cisco ios") ||
        lowerConfig.includes("version ") ||
        lowerConfig.includes("hostname ") ||
        lowerConfig.includes("interface ") ||
        lowerConfig.includes("ip access-list") ||
        lowerConfig.includes("transport input") ||
        lowerConfig.includes("enable secret")
    ) {
        vendor = "Cisco";
        confidence = 90;
    }


    // -----------------------------
    // JUNIPER
    // -----------------------------

    if (
        lowerConfig.includes("set system") ||
        lowerConfig.includes("set interfaces") ||
        lowerConfig.includes("set security") ||
        lowerConfig.includes("set protocols")
    ) {
        vendor = "Juniper";
        confidence = 90;
    }


    // -----------------------------
    // FORTINET
    // -----------------------------

    if (
        lowerConfig.includes("config system") ||
        lowerConfig.includes("config firewall") ||
        lowerConfig.includes("config vpn") ||
        lowerConfig.includes("set vdom") ||
        lowerConfig.includes("next") ||
        lowerConfig.includes("end")
    ) {
        vendor = "Fortinet";
        confidence = 90;
    }


    return {
        success: true,
        vendor: vendor,
        confidence: confidence
    };
}


module.exports = {
    detectVendor
};