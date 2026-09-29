const express = require("express");

const Configuration = require("../models/Configuration");
const Device = require("../models/Device");
const { runDriftDetection } = require("../services/driftService");

const router = express.Router();


// ==========================================
// CONFIGURATION DRIFT PAGE
// ==========================================

router.get("/", async (req, res) => {
    try {

        const userId = req.session.user.id;

        // Get user's devices
        const devices = await Device.find({
            user: userId
        }).select("_id");

        const deviceIds = devices.map(
            device => device._id
        );

        // Get only user's configurations
        const configurations = await Configuration
            .find({
                device: {
                    $in: deviceIds
                }
            })
            .populate("device")
            .sort({
                createdAt: -1
            });

        res.render("pages/configurationDrift", {
            configurations,
            result: null,
            oldConfig: null,
            newConfig: null
        });

    } catch (error) {

        console.error(
            "Drift page error:",
            error
        );

        res.status(500).send(
            "Failed to load configurations."
        );
    }
});


// ==========================================
// RUN DRIFT DETECTION
// ==========================================

router.post("/compare", async (req, res) => {

    try {

        const userId = req.session.user.id;

        const {
            oldConfiguration,
            newConfiguration
        } = req.body;


        if (
            !oldConfiguration ||
            !newConfiguration
        ) {
            return res.status(400).send(
                "Both configurations are required."
            );
        }


        if (
            oldConfiguration === newConfiguration
        ) {
            return res.status(400).send(
                "Old and new configuration cannot be the same."
            );
        }


        // ==========================================
        // GET OLD CONFIGURATION
        // ==========================================

        const oldConfig =
            await Configuration.findById(
                oldConfiguration
            ).populate("device");


        // ==========================================
        // GET NEW CONFIGURATION
        // ==========================================

        const newConfig =
            await Configuration.findById(
                newConfiguration
            ).populate("device");


        if (!oldConfig || !newConfig) {
            return res.status(404).send(
                "Configuration not found."
            );
        }


        // ==========================================
        // OWNERSHIP CHECK - OLD CONFIG
        // ==========================================

        if (
            !oldConfig.device ||
            !oldConfig.device.user ||
            oldConfig.device.user.toString() !== userId.toString()
        ) {
            return res.status(403).send(
                "Access denied."
            );
        }


        // ==========================================
        // OWNERSHIP CHECK - NEW CONFIG
        // ==========================================

        if (
            !newConfig.device ||
            !newConfig.device.user ||
            newConfig.device.user.toString() !== userId.toString()
        ) {
            return res.status(403).send(
                "Access denied."
            );
        }


        // ==========================================
        // RUN DRIFT DETECTION
        // ==========================================

        const driftResult =
            await runDriftDetection(
                oldConfig.filePath,
                newConfig.filePath
            );


        // ==========================================
        // RELOAD USER CONFIGURATIONS
        // ==========================================

        const devices = await Device.find({
            user: userId
        }).select("_id");

        const deviceIds = devices.map(
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


        // ==========================================
        // RENDER RESULT
        // ==========================================

        res.render(
            "pages/configurationDrift",
            {

                configurations,

                result: driftResult,

                oldConfig,

                newConfig

            }
        );


    } catch (error) {

        console.error(
            "Drift comparison error:",
            error
        );

        res.status(500).send(
            "Drift detection failed: " +
            error.message
        );
    }
});


module.exports = router;