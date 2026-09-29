const fs = require("fs");
const path = require("path");

function generateReportFile({
    audit,
    device,
    findings
}) {

    return new Promise((resolve, reject) => {

        try {

            const reportsDirectory = path.join(
                __dirname,
                "../reports"
            );


            // Create reports directory
            // if it doesn't exist

            if (!fs.existsSync(reportsDirectory)) {

                fs.mkdirSync(
                    reportsDirectory,
                    {
                        recursive: true
                    }
                );

            }


            const reportName =
                `NETSENTRY-Report-${audit._id}.txt`;


            const reportPath =
                path.join(
                    reportsDirectory,
                    reportName
                );


            let report = "";


            // ===============================
            // REPORT HEADER
            // ===============================

            report +=
                "========================================\n";

            report +=
                "          NETSENTRY SECURITY REPORT\n";

            report +=
                "========================================\n\n";


            // ===============================
            // DEVICE INFORMATION
            // ===============================

            report +=
                "DEVICE INFORMATION\n";

            report +=
                "----------------------------------------\n";

            report +=
                `Device Name: ${device.deviceName}\n`;

            report +=
                `Vendor: ${device.vendor}\n`;

            report +=
                `Device Type: ${device.deviceType}\n`;

            report +=
                `Status: ${device.status}\n`;

            report +=
                `Security Score: ${device.securityScore}%\n\n`;


            // ===============================
            // AUDIT INFORMATION
            // ===============================

            report +=
                "AUDIT INFORMATION\n";

            report +=
                "----------------------------------------\n";

            report +=
                `Audit ID: ${audit._id}\n`;

            report +=
                `Audit Status: ${audit.status}\n`;

            report +=
                `Vendor: ${audit.vendor}\n`;

            report +=
                `Compliance Score: ${audit.complianceScore}%\n`;

            report +=
                `Total Checks: ${audit.totalChecks}\n`;

            report +=
                `Passed Checks: ${audit.passedChecks}\n`;

            report +=
                `Failed Checks: ${audit.failedChecks}\n\n`;


            // ===============================
            // FINDING SUMMARY
            // ===============================

            report +=
                "FINDING SUMMARY\n";

            report +=
                "----------------------------------------\n";

            report +=
                `Critical: ${audit.criticalFindings}\n`;

            report +=
                `High: ${audit.highFindings}\n`;

            report +=
                `Medium: ${audit.mediumFindings}\n`;

            report +=
                `Low: ${audit.lowFindings}\n\n`;


            // ===============================
            // SECURITY FINDINGS
            // ===============================

            report +=
                "SECURITY FINDINGS\n";

            report +=
                "========================================\n\n";


            if (
                findings &&
                findings.length > 0
            ) {

                findings.forEach(
                    (finding, index) => {

                        report +=
                            `Finding ${index + 1}\n`;

                        report +=
                            "----------------------------------------\n";

                        report +=
                            `Title: ${finding.title}\n`;

                        report +=
                            `Severity: ${finding.severity}\n`;

                        report +=
                            `Category: ${finding.category}\n`;

                        report +=
                            `Status: ${finding.status}\n`;

                        report +=
                            `Description: ${finding.description}\n`;

                        report +=
                            `Detected Configuration: ${finding.detectedConfig || "N/A"}\n`;

                        report +=
                            `Recommended Fix: ${finding.recommendedFix || "N/A"}\n\n`;

                    }
                );

            } else {

                report +=
                    "No security findings detected.\n\n";

            }


            // ===============================
            // REPORT FOOTER
            // ===============================

            report +=
                "========================================\n";

            report +=
                "Report generated by NETSENTRY\n";

            report +=
                `Generated At: ${new Date().toISOString()}\n`;

            report +=
                "========================================\n";


            // Save report

            fs.writeFileSync(
                reportPath,
                report,
                "utf8"
            );


            resolve({
                success: true,
                reportName,
                reportPath
            });


        } catch (error) {

            reject(error);

        }

    });

}


module.exports = {
    generateReportFile
};