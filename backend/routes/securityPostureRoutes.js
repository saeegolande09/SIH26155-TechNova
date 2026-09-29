const express = require("express");

const Device = require("../models/Device");
const Finding = require("../models/Finding");
const Audit = require("../models/Audit");

const router = express.Router();

router.get("/", async (req, res) => {
    try {

        const userId = req.session.user.id;


        // ==========================================
        // GET CURRENT USER DEVICES
        // ==========================================

        const devices =
            await Device.find({
                user: userId
            })
            .sort({
                securityScore: 1
            });


        const deviceIds = devices.map(
            device => device._id
        );


        // ==========================================
        // TOTAL DEVICES
        // ==========================================

        const totalDevices =
            devices.length;


        // ==========================================
        // TOTAL AUDITS
        // ==========================================

        const totalAudits =
            await Audit.countDocuments({
                device: {
                    $in: deviceIds
                }
            });


        // ==========================================
        // COMPLETED AUDITS
        // ==========================================

        const completedAudits =
            await Audit.countDocuments({
                device: {
                    $in: deviceIds
                },
                status: "Completed"
            });


        // ==========================================
        // OPEN FINDINGS
        // ==========================================

        const openFindings =
            await Finding.countDocuments({
                device: {
                    $in: deviceIds
                },
                status: "Open"
            });


        // ==========================================
        // RESOLVED FINDINGS
        // ==========================================

        const resolvedFindings =
            await Finding.countDocuments({
                device: {
                    $in: deviceIds
                },
                status: "Resolved"
            });


        // ==========================================
        // CRITICAL FINDINGS
        // ==========================================

        const criticalFindings =
            await Finding.countDocuments({
                device: {
                    $in: deviceIds
                },
                severity: "Critical",
                status: "Open"
            });


        // ==========================================
        // HIGH FINDINGS
        // ==========================================

        const highFindings =
            await Finding.countDocuments({
                device: {
                    $in: deviceIds
                },
                severity: "High",
                status: "Open"
            });


        // ==========================================
        // MEDIUM FINDINGS
        // ==========================================

        const mediumFindings =
            await Finding.countDocuments({
                device: {
                    $in: deviceIds
                },
                severity: "Medium",
                status: "Open"
            });


        // ==========================================
        // LOW FINDINGS
        // ==========================================

        const lowFindings =
            await Finding.countDocuments({
                device: {
                    $in: deviceIds
                },
                severity: "Low",
                status: "Open"
            });


        // ==========================================
        // AVERAGE SECURITY SCORE
        // ==========================================

        const scoreResult =
            await Device.aggregate([

                {
                    $match: {
                        user: devices.length > 0
                            ? userId
                            : userId
                    }
                },

                {
                    $group: {
                        _id: null,

                        averageScore: {
                            $avg: "$securityScore"
                        }
                    }
                }

            ]);


        const averageScore =
            scoreResult.length > 0
                ? Math.round(
                    scoreResult[0].averageScore
                )
                : 0;


        // ==========================================
        // SECURITY POSTURE STATUS
        // ==========================================

        let postureStatus = "Unknown";


        if (averageScore >= 80) {

            postureStatus = "Strong";

        } else if (averageScore >= 60) {

            postureStatus = "Moderate";

        } else if (averageScore > 0) {

            postureStatus = "Needs Improvement";

        }


        // ==========================================
        // VENDOR SUMMARY
        // ==========================================

        const vendorSummary =
            await Device.aggregate([

                {
                    $match: {
                        user: userId
                    }
                },

                {
                    $group: {

                        _id: "$vendor",

                        deviceCount: {
                            $sum: 1
                        },

                        averageScore: {
                            $avg: "$securityScore"
                        }

                    }
                },

                {
                    $sort: {
                        deviceCount: -1
                    }
                }

            ]);


        // ==========================================
        // DEVICES WITH SCORE BELOW 60
        // ==========================================

        const riskyDevices =
            await Device.find({

                user: userId,

                securityScore: {
                    $lt: 60
                }

            })
            .sort({
                securityScore: 1
            });


        // ==========================================
        // RECENT AUDITS
        // ==========================================

        const recentAudits =
            await Audit.find({

                device: {
                    $in: deviceIds
                }

            })
            .populate("device")
            .sort({
                createdAt: -1
            })
            .limit(10);


        // ==========================================
        // RENDER PAGE
        // ==========================================

        res.render(
            "pages/securityPosture",
            {
                devices,

                totalDevices,

                totalAudits,

                completedAudits,

                averageScore,

                postureStatus,

                openFindings,

                resolvedFindings,

                criticalFindings,

                highFindings,

                mediumFindings,

                lowFindings,

                vendorSummary,

                riskyDevices,

                recentAudits
            }
        );


    } catch (error) {

        console.error(
            "Security posture error:",
            error
        );

        res.status(500).send(
            "Failed to load security posture."
        );
    }
});


module.exports = router;