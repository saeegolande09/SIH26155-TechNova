const express = require("express");
const path = require("path");
const fs = require("fs");

const Audit = require("../models/Audit");
const Device = require("../models/Device");
const Finding = require("../models/Finding");
const Report = require("../models/Report");

const {
    generatePDFReport
} = require("../services/pdfReportService");

const router = express.Router();


// =====================================
// REPORTS PAGE
// =====================================

router.get("/", async (req, res) => {

    try {

        const userId = req.session.user.id;

        // Get only user's devices
        const devices = await Device.find({
            user: userId
        }).select("_id");

        const deviceIds = devices.map(
            device => device._id
        );


        const audits = await Audit
            .find({
                status: "Completed",
                device: {
                    $in: deviceIds
                }
            })
            .populate("device")
            .sort({
                createdAt: -1
            });


        const reports = await Report
            .find({
                device: {
                    $in: deviceIds
                }
            })
            .populate("device")
            .populate("audit")
            .sort({
                createdAt: -1
            });


        res.render(
            "pages/reports",
            {
                audits,
                reports,
                generatedReport: null
            }
        );

    } catch (error) {

        console.error(
            "Reports page error:",
            error
        );

        res.status(500).send(
            "Failed to load reports."
        );
    }
});


// =====================================
// GENERATE PDF REPORT
// =====================================

router.post(
    "/generate",
    async (req, res) => {

        try {

            const userId = req.session.user.id;

            const {
                auditId
            } = req.body;


            if (!auditId) {

                return res.status(400).send(
                    "Audit is required."
                );

            }


            // =====================================
            // FIND AUDIT
            // =====================================

            const audit =
                await Audit.findById(auditId);

            if (!audit) {

                return res.status(404).send(
                    "Audit not found."
                );

            }


            // =====================================
            // FIND DEVICE
            // =====================================

            const device =
                await Device.findById(
                    audit.device
                );

            if (!device) {

                return res.status(404).send(
                    "Device not found."
                );

            }


            // =====================================
            // OWNERSHIP CHECK
            // =====================================

            if (
                !device.user ||
                device.user.toString() !== userId.toString()
            ) {

                return res.status(403).send(
                    "Access denied."
                );

            }


            // =====================================
            // FINDINGS
            // =====================================

            const findings =
                await Finding
                    .find({
                        audit: audit._id,
                        device: device._id
                    })
                    .sort({
                        createdAt: 1
                    });


            // =====================================
            // FINDING COUNTS
            // =====================================

            const criticalFindings =
                findings.filter(
                    f => f.severity === "Critical"
                ).length;


            const highFindings =
                findings.filter(
                    f => f.severity === "High"
                ).length;


            const mediumFindings =
                findings.filter(
                    f => f.severity === "Medium"
                ).length;


            const lowFindings =
                findings.filter(
                    f => f.severity === "Low"
                ).length;


            // =====================================
            // REPORT DIRECTORY
            // =====================================

            const reportsDirectory =
                path.join(
                    __dirname,
                    "../reports"
                );


            if (!fs.existsSync(reportsDirectory)) {

                fs.mkdirSync(
                    reportsDirectory,
                    {
                        recursive: true
                    }
                );

            }


            // =====================================
            // REPORT NAME
            // =====================================

            const reportName =
                `NETSENTRY-Report-${Date.now()}.pdf`;


            const reportPath =
                path.join(
                    reportsDirectory,
                    reportName
                );


            console.log(
                "Generating PDF report..."
            );


            // =====================================
            // GENERATE PDF
            // =====================================

            await generatePDFReport(

                {
                    auditId:
                        audit._id.toString(),

                    deviceName:
                        device.deviceName,

                    vendor:
                        device.vendor,

                    complianceScore:
                        audit.complianceScore,

                    totalChecks:
                        audit.totalChecks,

                    passedChecks:
                        audit.passedChecks,

                    failedChecks:
                        audit.failedChecks,

                    criticalFindings,

                    highFindings,

                    mediumFindings,

                    lowFindings,

                    findings

                },

                reportPath

            );


            // =====================================
            // SAVE REPORT IN DATABASE
            // =====================================

            const report =
                await Report.create({

                    audit:
                        audit._id,

                    device:
                        device._id,

                    reportName,

                    complianceScore:
                        audit.complianceScore,

                    totalFindings:
                        findings.length,

                    reportPath,

                    generatedAt:
                        new Date()

                });


            console.log(
                "PDF report generated successfully:",
                reportPath
            );


            // =====================================
            // RELOAD REPORT PAGE
            // =====================================

            const devicesAfter =
                await Device.find({
                    user: userId
                }).select("_id");


            const deviceIdsAfter =
                devicesAfter.map(
                    device => device._id
                );


            const audits =
                await Audit
                    .find({
                        status: "Completed",
                        device: {
                            $in: deviceIdsAfter
                        }
                    })
                    .populate("device")
                    .sort({
                        createdAt: -1
                    });


            const reports =
                await Report
                    .find({
                        device: {
                            $in: deviceIdsAfter
                        }
                    })
                    .populate("device")
                    .populate("audit")
                    .sort({
                        createdAt: -1
                    });


            res.render(
                "pages/reports",
                {
                    audits,
                    reports,
                    generatedReport: report
                }
            );


        } catch (error) {

            console.error(
                "PDF report generation error:",
                error
            );

            res.status(500).send(
                "PDF report generation failed: " +
                error.message
            );
        }
    }
);


// =====================================
// DOWNLOAD PDF REPORT
// =====================================

router.get(
    "/download/:id",
    async (req, res) => {

        try {

            const userId = req.session.user.id;


            const report =
                await Report.findById(
                    req.params.id
                );


            if (!report) {

                return res.status(404).send(
                    "Report not found."
                );

            }


            // =====================================
            // FIND REPORT DEVICE
            // =====================================

            const device =
                await Device.findById(
                    report.device
                );


            if (!device) {

                return res.status(404).send(
                    "Device not found."
                );

            }


            // =====================================
            // OWNERSHIP CHECK
            // =====================================

            if (
                !device.user ||
                device.user.toString() !== userId.toString()
            ) {

                return res.status(403).send(
                    "Access denied."
                );

            }


            if (!report.reportPath) {

                return res.status(404).send(
                    "Report file path not found."
                );

            }


            if (
                !fs.existsSync(
                    report.reportPath
                )
            ) {

                return res.status(404).send(
                    "Report PDF file does not exist."
                );

            }


            res.download(
                report.reportPath,
                report.reportName
            );


        } catch (error) {

            console.error(
                "Report download error:",
                error
            );

            res.status(500).send(
                "Failed to download report."
            );
        }
    }
);


module.exports = router;