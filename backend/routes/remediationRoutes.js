const express = require("express");
const fs = require("fs");
const path = require("path");

const Finding = require("../models/Finding");
const Remediation = require("../models/Remediation");
const Audit = require("../models/Audit");
const Configuration = require("../models/Configuration");
const Device = require("../models/Device");

const router = express.Router();


// ==========================================
// REMEDIATION PAGE
// ==========================================

router.get("/:findingId", async (req, res) => {
    try {

        const userId = req.session.user.id;

        const finding = await Finding.findById(req.params.findingId)
            .populate("device");

        if (!finding) {
            return res.status(404).send(
                "Finding not found."
            );
        }


        // ==========================================
        // OWNERSHIP CHECK
        // ==========================================

        if (
            !finding.device ||
            !finding.device.user ||
            finding.device.user.toString() !== userId.toString()
        ) {
            return res.status(403).send(
                "Access denied."
            );
        }


        let remediation = await Remediation.findOne({
            finding: finding._id
        });

        if (!remediation) {
            remediation = await Remediation.create({
                finding: finding._id,
                recommendedFix:
                    finding.recommendedFix ||
                    "No remediation available.",
                fixType: "Manual",
                status: "Pending"
            });
        }

        res.render("pages/remediation", {
            finding,
            remediation
        });

    } catch (error) {

        console.error("Remediation page error:", error);

        res.status(500).send(
            "Failed to load remediation."
        );
    }
});


// ==========================================
// APPLY FIX
// ==========================================

router.post("/:findingId/apply", async (req, res) => {

    try {

        const userId = req.session.user.id;

        const finding = await Finding.findById(
            req.params.findingId
        );

        if (!finding) {
            return res.status(404).send(
                "Finding not found."
            );
        }


        // ==========================================
        // FIND DEVICE
        // ==========================================

        const device = await Device.findById(
            finding.device
        );

        if (!device) {
            return res.status(404).send(
                "Device not found."
            );
        }


        // ==========================================
        // OWNERSHIP CHECK
        // ==========================================

        if (
            !device.user ||
            device.user.toString() !== userId.toString()
        ) {
            return res.status(403).send(
                "Access denied."
            );
        }


        // --------------------------------------
        // FIND ORIGINAL AUDIT
        // --------------------------------------

        const audit = await Audit.findById(
            finding.audit
        );

        if (!audit) {
            return res.status(404).send(
                "Audit not found."
            );
        }


        // --------------------------------------
        // FIND CONFIGURATION
        // --------------------------------------

        const configuration =
            await Configuration.findById(
                audit.configuration
            );

        if (!configuration) {
            return res.status(404).send(
                "Configuration not found."
            );
        }


        // --------------------------------------
        // READ CONFIGURATION FILE
        // --------------------------------------

        if (!fs.existsSync(configuration.filePath)) {
            return res.status(404).send(
                "Configuration file not found."
            );
        }

        let config = fs.readFileSync(
            configuration.filePath,
            "utf8"
        );


        // --------------------------------------
        // CISCO PLAINTEXT PASSWORD FIX
        // --------------------------------------

        if (
            finding.title ===
            "Plaintext Enable Password"
        ) {

            const passwordRegex =
                /^(\s*)enable\s+password\s+.+$/gim;

            if (!passwordRegex.test(config)) {

                return res.status(400).send(
                    "Plaintext enable password is not present in the configuration."
                );
            }


            config = config.replace(
                passwordRegex,
                "$1enable secret NETSENTRY_SECURE_SECRET"
            );
        }


        // --------------------------------------
        // CISCO TELNET FIX
        // --------------------------------------

        else if (
            finding.title ===
            "Telnet Enabled"
        ) {

            const telnetRegex =
                /^(\s*)transport\s+input\s+telnet\s*$/gim;

            if (!telnetRegex.test(config)) {

                return res.status(400).send(
                    "Telnet configuration is not present."
                );
            }


            config = config.replace(
                telnetRegex,
                "$1transport input ssh"
            );
        }


        else {

            return res.status(400).send(
                "Automatic remediation is not available for this finding yet."
            );
        }


        // --------------------------------------
        // SAVE UPDATED CONFIGURATION
        // --------------------------------------

        fs.writeFileSync(
            configuration.filePath,
            config,
            "utf8"
        );


        // --------------------------------------
        // UPDATE REMEDIATION
        // --------------------------------------

        let remediation =
            await Remediation.findOne({
                finding: finding._id
            });

        if (!remediation) {

            remediation =
                new Remediation({
                    finding: finding._id,
                    recommendedFix:
                        finding.recommendedFix ||
                        "Security fix applied.",
                    fixType: "Manual",
                    status: "Pending"
                });
        }


        remediation.status = "Applied";

        await remediation.save();


        res.redirect(
            `/remediations/${finding._id}`
        );

    } catch (error) {

        console.error(
            "Apply remediation error:",
            error
        );

        res.status(500).send(
            "Failed to apply remediation."
        );
    }
});


// ==========================================
// VERIFY FIX
// ==========================================

router.post("/:findingId/verify", async (req, res) => {

    try {

        const userId = req.session.user.id;

        const finding = await Finding.findById(
            req.params.findingId
        );

        if (!finding) {
            return res.status(404).send(
                "Finding not found."
            );
        }


        // ==========================================
        // FIND DEVICE
        // ==========================================

        const device = await Device.findById(
            finding.device
        );

        if (!device) {
            return res.status(404).send(
                "Device not found."
            );
        }


        // ==========================================
        // OWNERSHIP CHECK
        // ==========================================

        if (
            !device.user ||
            device.user.toString() !== userId.toString()
        ) {
            return res.status(403).send(
                "Access denied."
            );
        }


        const remediation =
            await Remediation.findOne({
                finding: finding._id
            });

        if (!remediation) {
            return res.status(404).send(
                "Remediation not found."
            );
        }


        if (remediation.status !== "Applied") {

            return res.status(400).send(
                "Fix must be applied before verification."
            );
        }


        remediation.status = "Verified";
        remediation.verifiedAt = new Date();

        await remediation.save();


        finding.status = "Resolved";
        finding.resolvedAt = new Date();

        await finding.save();


        res.redirect(
            `/remediations/${finding._id}`
        );

    } catch (error) {

        console.error(
            "Verify remediation error:",
            error
        );

        res.status(500).send(
            "Failed to verify remediation."
        );
    }
});


module.exports = router;