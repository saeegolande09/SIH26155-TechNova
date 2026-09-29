const express = require("express");
const fs = require("fs");
const path = require("path");

const Finding = require("../models/Finding");
const Remediation = require("../models/Remediation");
const Audit = require("../models/Audit");
const Configuration = require("../models/Configuration");

const router = express.Router();


// =====================================================
// REMEDIATION PAGE
// =====================================================

router.get("/:findingId", async (req, res) => {
    try {

        const finding = await Finding.findById(
            req.params.findingId
        ).populate("device");

        if (!finding) {
            return res.status(404).send("Finding not found.");
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

        return res.render(
            "pages/remediation",
            {
                finding,
                remediation
            }
        );

    } catch (error) {

        console.error("Remediation page error:", error);

        return res.status(500).send(
            "Failed to load remediation."
        );
    }
});


// =====================================================
// APPLY FIX
// =====================================================

router.post("/:findingId/apply", async (req, res) => {

    try {

        // =================================================
        // FINDING
        // =================================================

        const finding = await Finding.findById(
            req.params.findingId
        );

        if (!finding) {
            return res.status(404).send(
                "Finding not found."
            );
        }


        // =================================================
        // AUDIT
        // =================================================

        const audit = await Audit.findById(
            finding.audit
        );

        if (!audit) {
            return res.status(404).send(
                "Audit not found."
            );
        }


        // =================================================
        // CONFIGURATION
        // =================================================

        const configuration =
            await Configuration.findById(
                audit.configuration
            );

        if (!configuration) {
            return res.status(404).send(
                "Configuration not found."
            );
        }


        // =================================================
        // CONFIG PATH
        // =================================================

        let configPath =
            configuration.filePath;


        if (
            !configPath ||
            !fs.existsSync(configPath)
        ) {

            const fallbackPath =
                path.join(
                    __dirname,
                    "..",
                    "uploads",
                    configuration.fileName
                );

            if (
                fs.existsSync(fallbackPath)
            ) {
                configPath = fallbackPath;
            } else {
                return res.status(404).send(
                    "Configuration file not found."
                );
            }
        }


        // =================================================
        // READ CONFIG
        // =================================================

        let config =
            fs.readFileSync(
                configPath,
                "utf8"
            );


        // =================================================
        // NORMALIZE TITLE
        // =================================================

        const rawTitle =
            String(
                finding.title || ""
            ).trim();


        const title =
            rawTitle
                .toLowerCase()
                .replace(
                    /[^a-z0-9]+/g,
                    " "
                )
                .trim();


        console.log(
            "========================================"
        );

        console.log(
            "NETSENTRY REMEDIATION"
        );

        console.log(
            "Finding:",
            rawTitle
        );

        console.log(
            "Normalized:",
            title
        );

        console.log(
            "Detected:",
            finding.detectedConfig
        );

        console.log(
            "Vendor:",
            configuration.vendor
        );

        console.log(
            "File:",
            configPath
        );

        console.log(
            "========================================"
        );


        // =================================================
        // 1. ADMINISTRATIVE PASSWORD
        // =================================================

        if (
            title.includes("administrative") &&
            title.includes("password")
        ) {

            const detected =
                String(
                    finding.detectedConfig || ""
                ).trim();


            if (!detected) {

                return res.status(400).send(
                    "Administrative password configuration was not detected."
                );

            }


            // Supports:
            // set password "example-password"
            // set password example-password

            const passwordRegex =
                /set\s+password\s+(?:"[^"]*"|\S+)/i;


            if (
                !passwordRegex.test(
                    detected
                )
            ) {

                return res.status(400).send(
                    "Administrative password configuration format is not supported."
                );

            }


            if (
                !config.includes(
                    detected
                )
            ) {

                return res.status(400).send(
                    "Administrative password configuration was not found in the current configuration."
                );

            }


            const fixed =
                detected.replace(
                    passwordRegex,
                    'set password "NETSENTRY@2026#Secure"'
                );


            config =
                config.replace(
                    detected,
                    fixed
                );


            console.log(
                "Administrative password remediation applied."
            );

        }


        // =================================================
        // 2. PLAINTEXT PASSWORD
        // =================================================

        else if (
            title.includes("plaintext") &&
            title.includes("password")
        ) {

            const regex =
                /^(\s*)enable\s+password\s+.+$/im;


            if (
                !regex.test(
                    config
                )
            ) {

                return res.status(400).send(
                    "Plaintext enable password is not present in the configuration."
                );

            }


            config =
                config.replace(
                    regex,
                    "$1enable secret NETSENTRY_SECURE_SECRET"
                );

        }


        // =================================================
        // 3. TELNET
        // =================================================

        else if (
            title.includes("telnet")
        ) {

            const vendor =
                String(
                    configuration.vendor || ""
                ).toLowerCase();


            // -------------------------------------------------
            // FORTINET
            // -------------------------------------------------

            if (
                vendor === "fortinet" ||
                title.includes("access")
            ) {

                const regex =
                    /^(\s*set\s+allowaccess\b.*)$/gim;


                let changed =
                    false;


                config =
                    config.replace(
                        regex,
                        function (line) {

                            if (
                                !/\btelnet\b/i.test(
                                    line
                                )
                            ) {
                                return line;
                            }


                            changed = true;


                            return line.replace(
                                /\s+telnet\b/gi,
                                ""
                            );
                        }
                    );


                if (!changed) {

                    return res.status(400).send(
                        "Telnet access is not present in the configuration."
                    );
                }

            }

            // -------------------------------------------------
            // CISCO
            // -------------------------------------------------

            else {

                const regex =
                    /transport\s+input\s+telnet/gi;


                if (
                    !regex.test(
                        config
                    )
                ) {

                    return res.status(400).send(
                        "Telnet configuration is not present in the configuration."
                    );
                }


                config =
                    config.replace(
                        regex,
                        "transport input ssh"
                    );
            }
        }


        // =================================================
        // 4. SSH MANAGEMENT ACCESS
        // =================================================

        else if (
            title.includes("ssh")
        ) {

            const regex =
                /^(\s*set\s+allowaccess\b.*)$/gim;


            let changed =
                false;


            config =
                config.replace(
                    regex,
                    function (line) {

                        if (
                            !/\bssh\b/i.test(
                                line
                            )
                        ) {
                            return line;
                        }


                        changed = true;


                        return line.replace(
                            /\s+ssh\b/gi,
                            ""
                        );
                    }
                );


            // detectedConfig fallback

            if (
                !changed &&
                finding.detectedConfig
            ) {

                const detected =
                    String(
                        finding.detectedConfig
                    ).trim();


                if (
                    config.includes(
                        detected
                    )
                ) {

                    const fixed =
                        detected.replace(
                            /\s+ssh\b/gi,
                            ""
                        );


                    config =
                        config.replace(
                            detected,
                            fixed
                        );


                    changed = true;
                }
            }


            if (!changed) {

                return res.status(400).send(
                    "SSH management access is not present in the configuration."
                );
            }
        }


        // =================================================
        // 5. BROAD FIREWALL POLICY
        // =================================================

        else if (
            title.includes(
                "broad firewall policy"
            )
        ) {

            const detected =
                String(
                    finding.detectedConfig || ""
                ).trim();


            if (!detected) {

                return res.status(400).send(
                    "Detected firewall policy configuration is not available."
                );
            }


            let fixed = null;


            if (
                /set\s+srcaddr\s+"all"/i.test(
                    detected
                )
            ) {

                fixed =
                    detected.replace(
                        /set\s+srcaddr\s+"all"/i,
                        'set srcaddr "NETSENTRY_RESTRICTED_NETWORK"'
                    );

            }

            else if (
                /set\s+dstaddr\s+"all"/i.test(
                    detected
                )
            ) {

                fixed =
                    detected.replace(
                        /set\s+dstaddr\s+"all"/i,
                        'set dstaddr "NETSENTRY_RESTRICTED_NETWORK"'
                    );

            }


            if (!fixed) {

                return res.status(400).send(
                    "Unsupported Broad Firewall Policy configuration."
                );
            }


            if (
                !config.includes(
                    detected
                )
            ) {

                return res.status(400).send(
                    "Firewall policy configuration was not found in the current configuration."
                );
            }


            config =
                config.replace(
                    detected,
                    fixed
                );
        }


        // =================================================
        // 6. ALL SERVICES PERMITTED
        // =================================================

        else if (
            title.includes(
                "all services permitted"
            )
        ) {

            const detected =
                String(
                    finding.detectedConfig || ""
                ).trim();


            if (!detected) {

                return res.status(400).send(
                    "Detected service configuration is not available."
                );
            }


            if (
                !config.includes(
                    detected
                )
            ) {

                return res.status(400).send(
                    "Service configuration was not found in the current configuration."
                );
            }


            const fixed =
                detected.replace(
                    /set\s+service\s+"all"/i,
                    'set service "HTTPS"'
                );


            config =
                config.replace(
                    detected,
                    fixed
                );
        }


        // =================================================
        // 7. JUNIPER BROAD SECURITY POLICY
        // =================================================

        else if (
            title.includes(
                "broad security policy"
            )
        ) {

            const detected =
                String(
                    finding.detectedConfig || ""
                ).trim();


            if (!detected) {

                return res.status(400).send(
                    "Detected Juniper policy configuration is not available."
                );
            }


            if (
                !config.includes(
                    detected
                )
            ) {

                return res.status(400).send(
                    "Juniper security policy configuration was not found."
                );
            }


            config =
                config.replace(
                    detected,
                    ""
                );
        }


        // =================================================
        // 8. UNSUPPORTED
        // =================================================

        else {

            return res.status(400).send(
                "Automatic remediation is not available for this finding yet. Finding: " +
                rawTitle
            );
        }


        // =================================================
        // SAVE CONFIGURATION
        // =================================================

        fs.writeFileSync(
            configPath,
            config,
            "utf8"
        );


        // =================================================
        // UPDATE REMEDIATION
        // =================================================

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

                    fixType: "Automated",

                    status: "Pending"
                });
        }


        remediation.status =
            "Applied";

        remediation.fixType =
            "Automated";


        await remediation.save();


        // =================================================
        // REDIRECT
        // =================================================

        return res.redirect(
            `/remediations/${finding._id}`
        );


    } catch (error) {

        console.error(
            "Apply remediation error:",
            error
        );

        return res.status(500).send(
            "Failed to apply remediation: " +
            error.message
        );
    }
});


// =====================================================
// VERIFY FIX
// =====================================================

router.post(
    "/:findingId/verify",
    async (req, res) => {

        try {

            const finding =
                await Finding.findById(
                    req.params.findingId
                );


            if (!finding) {

                return res.status(404).send(
                    "Finding not found."
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


            if (
                remediation.status !==
                "Applied"
            ) {

                return res.status(400).send(
                    "Fix must be applied before verification."
                );
            }


            remediation.status =
                "Verified";

            remediation.verifiedAt =
                new Date();


            await remediation.save();


            finding.status =
                "Resolved";

            finding.resolvedAt =
                new Date();


            await finding.save();


            return res.redirect(
                `/remediations/${finding._id}`
            );


        } catch (error) {

            console.error(
                "Verify remediation error:",
                error
            );

            return res.status(500).send(
                "Failed to verify remediation."
            );
        }
    }
);


module.exports = router;