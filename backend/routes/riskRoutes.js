const express = require("express");

const Finding = require("../models/Finding");
const Device = require("../models/Device");

const router = express.Router();

router.get("/", async (req, res) => {

    try {

        const userId = req.session.user.id;


        // ==========================================
        // GET USER DEVICES
        // ==========================================

        const devices = await Device.find({
            user: userId
        }).select("_id");


        const deviceIds = devices.map(
            device => device._id
        );


        // ==========================================
        // GET OPEN FINDINGS
        // ONLY CURRENT USER
        // ==========================================

        const findings = await Finding.find({
            status: "Open",
            device: {
                $in: deviceIds
            }
        })
            .populate("device")
            .sort({
                createdAt: -1
            });


        // ==========================================
        // PRIORITY ORDER
        // ==========================================

        const priorityOrder = {
            Critical: 1,
            High: 2,
            Medium: 3,
            Low: 4,
            Informational: 5
        };


        // ==========================================
        // RISK SCORE
        // ==========================================

        const riskScore = {
            Critical: 100,
            High: 75,
            Medium: 50,
            Low: 25,
            Informational: 10
        };


        // ==========================================
        // SORT FINDINGS
        // ==========================================

        findings.sort((a, b) => {

            const priorityDifference =
                priorityOrder[a.severity] -
                priorityOrder[b.severity];

            if (priorityDifference !== 0) {
                return priorityDifference;
            }

            return (
                new Date(b.createdAt) -
                new Date(a.createdAt)
            );

        });


        // ==========================================
        // ADD RISK SCORE
        // ==========================================

        findings.forEach((finding) => {

            finding.riskScore =
                riskScore[finding.severity] || 0;

        });


        // ==========================================
        // FINDINGS BY SEVERITY
        // ==========================================

        const criticalFindings =
            findings.filter(
                finding =>
                    finding.severity === "Critical"
            );


        const highFindings =
            findings.filter(
                finding =>
                    finding.severity === "High"
            );


        const mediumFindings =
            findings.filter(
                finding =>
                    finding.severity === "Medium"
            );


        const lowFindings =
            findings.filter(
                finding =>
                    finding.severity === "Low"
            );


        const informationalFindings =
            findings.filter(
                finding =>
                    finding.severity === "Informational"
            );


        // ==========================================
        // TOTAL OPEN FINDINGS
        // ==========================================

        const totalOpenFindings =
            findings.length;


        // ==========================================
        // HIGHEST PRIORITY FINDING
        // ==========================================

        const highestPriorityFinding =
            findings.length > 0
                ? findings[0]
                : null;


        // ==========================================
        // RENDER PAGE
        // ==========================================

        res.render(
            "pages/riskPrioritization",
            {

                findings,

                totalOpenFindings,

                criticalFindings,

                highFindings,

                mediumFindings,

                lowFindings,

                informationalFindings,

                highestPriorityFinding

            }
        );


    } catch (error) {

        console.error(
            "Risk prioritization error:",
            error
        );


        res.status(500).send(
            "Failed to load risk prioritization."
        );

    }

});


module.exports = router;