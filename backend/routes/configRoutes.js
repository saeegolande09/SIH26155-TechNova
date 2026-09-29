const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const Device = require("../models/Device");
const Configuration = require("../models/Configuration");
const Audit = require("../models/Audit");
const Finding = require("../models/Finding");

const { runSecurityAudit } = require("../services/auditService");
const { detectVendor } = require("../services/vendorDetection");
const { runNormalization } = require("../services/normalizationService");

const router = express.Router();


// ==========================================
// UPLOAD DIRECTORY
// ==========================================

const uploadDirectory = path.join(
    __dirname,
    "../uploads"
);

if (!fs.existsSync(uploadDirectory)) {

    fs.mkdirSync(
        uploadDirectory,
        {
            recursive: true
        }
    );

}


// ==========================================
// MULTER STORAGE
// ==========================================

const storage = multer.diskStorage({

    destination: function (req, file, cb) {

        cb(
            null,
            uploadDirectory
        );

    },

    filename: function (req, file, cb) {

        let originalName =
            file.originalname;

        originalName =
            originalName.replace(
                /(\.txt)+$/i,
                ""
            );

        const finalName =
            Date.now() +
            "-" +
            originalName +
            ".txt";

        cb(
            null,
            finalName
        );

    }

});


const upload = multer({
    storage: storage
});


// ==========================================
// UPLOAD PAGE
// ==========================================

router.get(
    "/upload",
    async (req, res) => {

        try {

            res.render(
                "pages/uploadConfig"
            );

        } catch (error) {

            console.error(
                "Upload page error:",
                error
            );

            res.status(500).send(
                "Failed to load upload page."
            );

        }

    }
);


// ==========================================
// UPLOAD + VENDOR DETECTION
// + NORMALIZATION + AUDIT
// ==========================================

router.post(
    "/upload",
    upload.single("configFile"),
    async (req, res) => {

        try {

            // ======================================
            // CHECK FILE
            // ======================================

            if (!req.file) {

                return res.status(400).send(
                    "Configuration file is required."
                );

            }


            // ======================================
            // CHECK LOGIN
            // ======================================

            if (
                !req.session ||
                !req.session.user
            ) {

                return res.status(401).send(
                    "Login required."
                );

            }


            // ======================================
            // DEVICE NAME
            // ======================================

            const deviceName =
                req.body.deviceName ||
                "Unknown Device";


            // ======================================
            // VENDOR DETECTION
            // ======================================

            const detectedVendor =
                detectVendor(
                    req.file.path
                );


            if (!detectedVendor.success) {

                return res.status(400).send(
                    detectedVendor.message
                );

            }


            const vendor =
                detectedVendor.vendor;


            console.log(
                "Detected Vendor:",
                vendor
            );


            console.log(
                "Detection Confidence:",
                detectedVendor.confidence + "%"
            );


            // ======================================
            // NORMALIZATION
            // ======================================

            console.log(
                "Starting configuration normalization..."
            );


            const normalizedConfig =
                await runNormalization(
                    req.file.path,
                    vendor
                );


            if (!normalizedConfig.success) {

                return res.status(500).send(
                    normalizedConfig.message ||
                    "Configuration normalization failed."
                );

            }


            console.log(
                "Configuration normalization completed."
            );


            console.log(
                "Normalized Vendor:",
                normalizedConfig.vendor
            );


            console.log(
                "Normalized Hostname:",
                normalizedConfig.hostname
            );


            // ======================================
            // CREATE DEVICE
            // ======================================

            const device =
                await Device.create({

                    user:
                        req.session.user.id,

                    deviceName:
                        deviceName,

                    vendor:
                        vendor,

                    deviceType:
                        "Network Device",

                    status:
                        "Active"

                });


            // ======================================
            // CREATE CONFIGURATION
            // ======================================

            const configuration =
                await Configuration.create({

                    device:
                        device._id,

                    fileName:
                        req.file.filename,

                    vendor:
                        vendor,

                    filePath:
                        req.file.path,

                    configVersion:
                        "1.0",

                    status:
                        "Uploaded"

                });


            // ======================================
            // CREATE AUDIT
            // ======================================

            const audit =
                await Audit.create({

                    device:
                        device._id,

                    configuration:
                        configuration._id,

                    vendor:
                        vendor,

                    status:
                        "Running",

                    startedAt:
                        new Date()

                });


            // ======================================
            // RUN SECURITY ENGINE
            // ======================================

            console.log(
                "Starting security audit..."
            );


            const auditResult =
                await runSecurityAudit(
                    configuration.filePath,
                    vendor
                );


            console.log(
                "Security audit completed."
            );


            // ======================================
            // CHECK AUDIT RESULT
            // ======================================

            if (!auditResult.success) {

                audit.status =
                    "Failed";

                await audit.save();


                configuration.status =
                    "Failed";

                await configuration.save();


                return res.status(500).send(
                    auditResult.message ||
                    "Security audit failed."
                );

            }


            // ======================================
            // SAVE FINDINGS
            // ======================================

            const savedFindings = [];


            for (
                const finding
                of auditResult.findings
            ) {

                const savedFinding =
                    await Finding.create({

                        audit:
                            audit._id,

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


                savedFindings.push(
                    savedFinding
                );

            }


            // ======================================
            // FINDING COUNTS
            // ======================================

            const criticalFindings =
                auditResult.criticalFindings || 0;


            const highFindings =
                auditResult.highFindings || 0;


            const mediumFindings =
                auditResult.mediumFindings || 0;


            const lowFindings =
                auditResult.lowFindings || 0;


            // ======================================
            // UPDATE AUDIT
            // ======================================

            audit.status =
                "Completed";


            audit.complianceScore =
                auditResult.complianceScore || 0;


            audit.totalChecks =
                auditResult.totalChecks || 0;


            audit.passedChecks =
                auditResult.passedChecks || 0;


            audit.failedChecks =
                auditResult.failedChecks || 0;


            audit.criticalFindings =
                criticalFindings;


            audit.highFindings =
                highFindings;


            audit.mediumFindings =
                mediumFindings;


            audit.lowFindings =
                lowFindings;


            audit.completedAt =
                new Date();


            await audit.save();


            // ======================================
            // UPDATE CONFIGURATION
            // ======================================

            configuration.status =
                "Analyzed";


            await configuration.save();


            // ======================================
            // UPDATE DEVICE
            // ======================================

            device.securityScore =
                auditResult.complianceScore || 0;


            device.lastAudit =
                new Date();


            await device.save();


            // ======================================
            // AUDIT SUMMARY LOG
            // ======================================

            console.log(
                "================================"
            );


            console.log(
                "AUDIT COMPLETED"
            );


            console.log(
                "Vendor:",
                vendor
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
                criticalFindings
            );


            console.log(
                "High:",
                highFindings
            );


            console.log(
                "Medium:",
                mediumFindings
            );


            console.log(
                "Low:",
                lowFindings
            );


            console.log(
                "================================"
            );


            // ======================================
            // RENDER RESULTS
            // ======================================

            res.render(
                "pages/auditResults",
                {

                    device,

                    configuration,

                    audit,

                    findings:
                        savedFindings,

                    vendorDetection:
                        detectedVendor,

                    normalizedConfig:
                        normalizedConfig,

                    ruleStatus:
                        auditResult.ruleStatus || {}

                }
            );


        } catch (error) {

            console.error(
                "Configuration upload error:",
                error
            );


            res.status(500).send(
                "Configuration upload failed: " +
                error.message
            );

        }

    }
);


// ==========================================
// CONFIGURATION LIST
// ==========================================

router.get(
    "/",
    async (req, res) => {

        try {

            if (
                !req.session ||
                !req.session.user
            ) {

                return res.status(401).send(
                    "Login required."
                );

            }


            // ======================================
            // GET ONLY DEVICES OWNED BY USER
            // ======================================

            const userDevices =
                await Device.find({

                    user:
                        req.session.user.id

                }).select("_id");


            const deviceIds =
                userDevices.map(
                    device => device._id
                );


            const configurations =
                await Configuration
                    .find({

                        device: {
                            $in: deviceIds
                        }

                    })
                    .populate("device")
                    .sort({
                        createdAt: -1
                    });


            res.render(
                "pages/configurations",
                {
                    configurations
                }
            );


        } catch (error) {

            console.error(
                "Configuration list error:",
                error
            );


            res.status(500).send(
                "Failed to load configurations."
            );

        }

    }
);


module.exports = router;