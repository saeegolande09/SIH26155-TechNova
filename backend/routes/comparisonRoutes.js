const express = require("express");

const Configuration = require("../models/Configuration");
const Device = require("../models/Device");

const { runDriftDetection } = require("../services/driftService");

const router = express.Router();


// ===============================
// DEVICE COMPARISON PAGE
// ===============================

router.get("/", async (req, res) => {

    try {

        const userId = req.session.user.id;


        // ===============================
        // GET USER DEVICES
        // ===============================

        const devices = await Device
            .find({
                user: userId
            })
            .select("_id");


        const deviceIds = devices.map(
            device => device._id
        );


        // ===============================
        // GET USER CONFIGURATIONS
        // ===============================

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


        res.render(
            "pages/deviceComparison",
            {

                configurations,

                result: null,

                oldConfiguration: null,

                newConfiguration: null

            }
        );


    } catch (error) {

        console.error(
            "Device comparison page error:",
            error
        );

        res.status(500).send(
            "Failed to load device comparison."
        );
    }
});


// ===============================
// COMPARE TWO CONFIGURATIONS
// ===============================

router.post("/compare", async (req, res) => {

    try {

        const userId = req.session.user.id;


        const {
            oldConfigurationId,
            newConfigurationId
        } = req.body;


        // ===============================
        // CHECK CONFIGURATION SELECTION
        // ===============================

        if (
            !oldConfigurationId ||
            !newConfigurationId
        ) {

            return res.status(400).send(
                "Both configurations are required."
            );
        }


        // ===============================
        // PREVENT SAME CONFIGURATION
        // ===============================

        if (
            oldConfigurationId ===
            newConfigurationId
        ) {

            return res.status(400).send(
                "Please select two different configurations."
            );
        }


        // ===============================
        // FIND OLD CONFIGURATION
        // ===============================

        const oldConfiguration =
            await Configuration
                .findById(oldConfigurationId)
                .populate("device");


        // ===============================
        // FIND NEW CONFIGURATION
        // ===============================

        const newConfiguration =
            await Configuration
                .findById(newConfigurationId)
                .populate("device");


        // ===============================
        // CHECK OLD CONFIGURATION
        // ===============================

        if (!oldConfiguration) {

            return res.status(404).send(
                "Old configuration not found."
            );
        }


        // ===============================
        // CHECK NEW CONFIGURATION
        // ===============================

        if (!newConfiguration) {

            return res.status(404).send(
                "New configuration not found."
            );
        }


        // ===============================
        // OWNERSHIP CHECK - OLD
        // ===============================

        if (
            !oldConfiguration.device ||
            !oldConfiguration.device.user ||
            oldConfiguration.device.user.toString() !==
            userId.toString()
        ) {

            return res.status(403).send(
                "Access denied."
            );
        }


        // ===============================
        // OWNERSHIP CHECK - NEW
        // ===============================

        if (
            !newConfiguration.device ||
            !newConfiguration.device.user ||
            newConfiguration.device.user.toString() !==
            userId.toString()
        ) {

            return res.status(403).send(
                "Access denied."
            );
        }


        console.log(
            "================================"
        );

        console.log(
            "Starting configuration comparison..."
        );

        console.log(
            "Old Configuration:",
            oldConfiguration.fileName
        );

        console.log(
            "New Configuration:",
            newConfiguration.fileName
        );


        // ===============================
        // RUN PYTHON DRIFT ENGINE
        // ===============================

        const result =
            await runDriftDetection(

                oldConfiguration.filePath,

                newConfiguration.filePath

            );


        console.log(
            "Configuration comparison completed."
        );

        console.log(
            "Drift Detected:",
            result.driftDetected
        );

        console.log(
            "Changed Lines:",
            result.changedLines
        );

        console.log(
            "Risk Level:",
            result.riskLevel
        );

        console.log(
            "================================"
        );


        // ===============================
        // RELOAD USER CONFIGURATIONS
        // ===============================

        const devices = await Device
            .find({
                user: userId
            })
            .select("_id");


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


        // ===============================
        // RENDER COMPARISON RESULT
        // ===============================

        res.render(
            "pages/deviceComparison",
            {

                configurations,

                result,

                oldConfiguration,

                newConfiguration

            }
        );


    } catch (error) {

        console.error(
            "Device comparison error:",
            error
        );

        res.status(500).send(
            "Device comparison failed: " +
            error.message
        );
    }
});


module.exports = router;