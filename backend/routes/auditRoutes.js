const express = require("express");

const Audit = require("../models/Audit");
const Configuration = require("../models/Configuration");
const Device = require("../models/Device");
const Finding = require("../models/Finding");

const {
    runSecurityAudit
} = require("../services/auditService");

const router = express.Router();


// ==========================================
// SHOW ALL AUDITS
// ==========================================

router.get("/", async (req, res) => {
    try {

        const userId = req.session.user.id;

        // Get only user's devices
        const devices = await Device.find({
            user: userId
        }).select("_id");

        const deviceIds = devices.map(device => device._id);

        // Get only audits belonging to user's devices
        const audits = await Audit.find({
            device: {
                $in: deviceIds
            }
        })
            .populate("device")
            .populate("configuration")
            .sort({ createdAt: -1 });

        res.render("pages/audits", {
            audits
        });

    } catch (error) {

        console.error("Audit listing error:", error);

        res.status(500).send(
            "Failed to load audits."
        );
    }
});


// ==========================================
// SHOW AUDIT DETAILS
// ==========================================

router.get("/:auditId", async (req, res) => {
    try {

        const userId = req.session.user.id;

        // Get audit and device
        const audit = await Audit.findById(
            req.params.auditId
        )
            .populate("device")
            .populate("configuration");

        if (!audit) {
            return res.status(404).send(
                "Audit not found."
            );
        }

        // Ownership check
        if (
            !audit.device ||
            audit.device.user.toString() !== userId.toString()
        ) {
            return res.status(403).send(
                "Access denied."
            );
        }

        const findings = await Finding.find({
            audit: audit._id
        }).sort({
            severity: 1,
            createdAt: -1
        });

        res.render("pages/auditDetails", {
            audit,
            findings
        });

    } catch (error) {

        console.error(
            "Audit details error:",
            error
        );

        res.status(500).send(
            "Failed to load audit details."
        );
    }
});


// ==========================================
// SHOW RE-AUDIT PAGE
// ==========================================

router.get(
    "/:auditId/reaudit",
    async (req, res) => {

        try {

            const userId = req.session.user.id;

            // ======================================
            // GET OLD AUDIT
            // ======================================

            const oldAudit =
                await Audit.findById(
                    req.params.auditId
                );

            if (!oldAudit) {

                return res.status(404).send(
                    "Audit not found."
                );

            }


            // ======================================
            // GET DEVICE
            // ======================================

            const device =
                await Device.findById(
                    oldAudit.device
                );

            if (!device) {

                return res.status(404).send(
                    "Device not found."
                );

            }


            // ======================================
            // OWNERSHIP CHECK
            // ======================================

            if (
                !device.user ||
                device.user.toString() !== userId.toString()
            ) {
                return res.status(403).send(
                    "Access denied."
                );
            }


            // ======================================
            // GET CONFIGURATION
            // ======================================

            const configuration =
                await Configuration.findById(
                    oldAudit.configuration
                );


            if (!configuration) {

                return res.status(404).send(
                    "Configuration not found."
                );

            }


            // ======================================
            // RENDER RE-AUDIT PAGE
            // ======================================

            res.render(
                "pages/reAudit",
                {
                    audit: oldAudit,
                    device,
                    configuration,
                    completed: false
                }
            );


        } catch (error) {

            console.error(
                "Re-audit page error:",
                error
            );

            res.status(500).send(
                "Failed to load re-audit."
            );

        }

    }
);


// ==========================================
// RUN RE-AUDIT
// ==========================================

router.post(
    "/:auditId/reaudit",
    async (req, res) => {

        try {

            const userId = req.session.user.id;


            // ======================================
            // GET OLD AUDIT
            // ======================================

            const oldAudit =
                await Audit.findById(
                    req.params.auditId
                );


            if (!oldAudit) {

                return res.status(404).send(
                    "Audit not found."
                );

            }


            // ======================================
            // GET DEVICE
            // ======================================

            const device =
                await Device.findById(
                    oldAudit.device
                );


            if (!device) {

                return res.status(404).send(
                    "Device not found."
                );

            }


            // ======================================
            // OWNERSHIP CHECK
            // ======================================

            if (
                !device.user ||
                device.user.toString() !== userId.toString()
            ) {
                return res.status(403).send(
                    "Access denied."
                );
            }


            // ======================================
            // GET CONFIGURATION
            // ======================================

            const configuration =
                await Configuration.findById(
                    oldAudit.configuration
                );


            if (!configuration) {

                return res.status(404).send(
                    "Configuration not found."
                );

            }


            console.log(
                "================================"
            );

            console.log(
                "Starting re-audit..."
            );


            // ======================================
            // RUN PYTHON SECURITY ENGINE
            // ======================================

            const auditResult =
                await runSecurityAudit(
                    configuration.filePath,
                    oldAudit.vendor
                );


            console.log(
                "Re-audit completed."
            );


            // ======================================
            // CHECK RESULT
            // ======================================

            if (!auditResult.success) {

                return res.status(500).send(
                    auditResult.message ||
                    "Re-audit failed."
                );

            }


            // ======================================
            // CREATE NEW AUDIT
            // ======================================

            const newAudit =
                await Audit.create({

                    device:
                        device._id,

                    configuration:
                        configuration._id,

                    vendor:
                        oldAudit.vendor,

                    status:
                        "Completed",

                    complianceScore:
                        auditResult.complianceScore || 0,

                    totalChecks:
                        auditResult.totalChecks || 0,

                    passedChecks:
                        auditResult.passedChecks || 0,

                    failedChecks:
                        auditResult.failedChecks || 0,

                    criticalFindings:
                        auditResult.criticalFindings || 0,

                    highFindings:
                        auditResult.highFindings || 0,

                    mediumFindings:
                        auditResult.mediumFindings || 0,

                    lowFindings:
                        auditResult.lowFindings || 0,

                    startedAt:
                        new Date(),

                    completedAt:
                        new Date()

                });


            // ======================================
            // SAVE NEW FINDINGS
            // ======================================

            const findings = [];


            for (
                const finding
                of auditResult.findings
            ) {

                const savedFinding =
                    await Finding.create({

                        audit:
                            newAudit._id,

                        device:
                            device._id,

                        title:
                            finding.title,

                        category:
                            finding.category,

                        severity:
                            finding.severity,

                        description:
                            finding.description,

                        detectedConfig:
                            finding.detectedConfig,

                        recommendedFix:
                            finding.recommendedFix,

                        status:
                            "Open"

                    });


                findings.push(
                    savedFinding
                );

            }


            // ======================================
            // UPDATE DEVICE
            // ======================================

            device.securityScore =
                auditResult.complianceScore || 0;


            device.lastAudit =
                new Date();


            await device.save();


            // ======================================
            // UPDATE CONFIGURATION
            // ======================================

            configuration.status =
                "Analyzed";


            await configuration.save();


            // ======================================
            // LOG RESULT
            // ======================================

            console.log(
                "--------------------------------"
            );

            console.log(
                "RE-AUDIT RESULT"
            );

            console.log(
                "Vendor:",
                oldAudit.vendor
            );

            console.log(
                "Score:",
                auditResult.complianceScore + "%"
            );

            console.log(
                "Total Checks:",
                auditResult.totalChecks
            );

            console.log(
                "Passed:",
                auditResult.passedChecks
            );

            console.log(
                "Failed:",
                auditResult.failedChecks
            );

            console.log(
                "Critical:",
                auditResult.criticalFindings
            );

            console.log(
                "High:",
                auditResult.highFindings
            );

            console.log(
                "Medium:",
                auditResult.mediumFindings
            );

            console.log(
                "Low:",
                auditResult.lowFindings
            );

            console.log(
                "--------------------------------"
            );


            // ======================================
            // RENDER RESULT
            // ======================================

            res.render(
                "pages/reAudit",
                {

                    audit:
                        newAudit,

                    device,

                    configuration,

                    findings,

                    ruleStatus:
                        auditResult.ruleStatus || {},

                    completed:
                        true

                }
            );


        } catch (error) {

            console.error(
                "Re-audit error:",
                error
            );

            res.status(500).send(
                "Re-audit failed: " +
                error.message
            );

        }

    }
);


module.exports = router;