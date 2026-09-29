const PDFDocument = require("pdfkit");
const fs = require("fs");
const path = require("path");

function generatePDFReport(data, outputPath) {

    return new Promise((resolve, reject) => {

        try {

            const doc = new PDFDocument({
                margin: 50
            });

            const stream =
                fs.createWriteStream(outputPath);

            doc.pipe(stream);

            // ===============================
            // TITLE
            // ===============================

            doc
                .fontSize(24)
                .text("NETSENTRY AI", {
                    align: "center"
                });

            doc
                .moveDown(0.5)
                .fontSize(14)
                .text(
                    "Multi-Vendor Network Security Compliance Audit",
                    {
                        align: "center"
                    }
                );

            doc.moveDown(2);

            // ===============================
            // AUDIT INFORMATION
            // ===============================

            doc
                .fontSize(16)
                .text("Audit Report");

            doc.moveDown(0.5);

            doc
                .fontSize(11)
                .text(
                    `Device: ${data.deviceName || "Unknown"}`
                );

            doc.text(
                `Vendor: ${data.vendor || "Unknown"}`
            );

            doc.text(
                `Audit ID: ${data.auditId || "N/A"}`
            );

            doc.text(
                `Generated: ${new Date().toLocaleString()}`
            );

            doc.moveDown(1.5);

            // ===============================
            // COMPLIANCE SCORE
            // ===============================

            doc
                .fontSize(18)
                .text("Compliance Score");

            doc
                .moveDown(0.5)
                .fontSize(28)
                .text(
                    `${data.complianceScore || 0}%`,
                    {
                        align: "center"
                    }
                );

            doc.moveDown(1.5);

            // ===============================
            // SUMMARY
            // ===============================

            doc
                .fontSize(16)
                .text("Audit Summary");

            doc.moveDown(0.5);

            doc
                .fontSize(11)
                .text(
                    `Total Checks: ${data.totalChecks || 0}`
                );

            doc.text(
                `Passed Checks: ${data.passedChecks || 0}`
            );

            doc.text(
                `Failed Checks: ${data.failedChecks || 0}`
            );

            doc.text(
                `Critical Findings: ${data.criticalFindings || 0}`
            );

            doc.text(
                `High Findings: ${data.highFindings || 0}`
            );

            doc.text(
                `Medium Findings: ${data.mediumFindings || 0}`
            );

            doc.text(
                `Low Findings: ${data.lowFindings || 0}`
            );

            doc.moveDown(1.5);

            // ===============================
            // FINDINGS
            // ===============================

            doc
                .fontSize(16)
                .text("Security Findings");

            doc.moveDown(0.8);

            const findings =
                data.findings || [];

            if (findings.length === 0) {

                doc
                    .fontSize(11)
                    .text(
                        "No security findings detected."
                    );

            } else {

                findings.forEach(
                    (finding, index) => {

                        doc
                            .fontSize(13)
                            .text(
                                `${index + 1}. ${finding.title || "Security Finding"}`
                            );

                        doc
                            .fontSize(10)
                            .text(
                                `Severity: ${finding.severity || "Unknown"}`
                            );

                        doc.text(
                            `Category: ${finding.category || "Other"}`
                        );

                        if (finding.description) {

                            doc.text(
                                `Description: ${finding.description}`
                            );

                        }

                        if (finding.detectedConfig) {

                            doc.text(
                                `Detected Configuration: ${finding.detectedConfig}`
                            );

                        }

                        if (finding.recommendedFix) {

                            doc.text(
                                `Recommended Fix: ${finding.recommendedFix}`
                            );

                        }

                        doc.moveDown(0.8);
                    }
                );
            }

            // ===============================
            // FOOTER
            // ===============================

            doc.moveDown(1);

            doc
                .fontSize(9)
                .text(
                    "Generated by NETSENTRY AI",
                    {
                        align: "center"
                    }
                );

            doc
                .fontSize(8)
                .text(
                    "AI-Driven Multi-Vendor Network Security Compliance Auditor",
                    {
                        align: "center"
                    }
                );

            doc.end();

            stream.on(
                "finish",
                () => resolve(outputPath)
            );

            stream.on(
                "error",
                reject
            );

        } catch (error) {

            reject(error);

        }

    });
}

module.exports = {
    generatePDFReport
};