const express = require("express");

const Configuration = require("../models/Configuration");
const Device = require("../models/Device");

const {
    runExposureAnalysis
} = require("../services/exposureService");

const router = express.Router();


// ==========================================
// EXPOSURE ANALYSIS PAGE
// ==========================================

router.get("/", async (req, res) => {

    try {

        const userId = req.session.user.id;


        // ==========================================
        // GET USER DEVICES
        // ==========================================

        const devices = await Device
            .find({
                user: userId
            })
            .select("_id");


        const deviceIds = devices.map(
            device => device._id
        );


        // ==========================================
        // GET USER CONFIGURATIONS
        // ==========================================

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
            "pages/exposureAnalysis",
            {
                configurations,
                result: null,
                selectedConfiguration: null
            }
        );


    } catch (error) {

        console.error(
            "Exposure page error:",
            error
        );

        res.status(500).send(
            "Failed to load exposure analysis."
        );
    }
});


// ==========================================
// RUN EXPOSURE ANALYSIS
// ==========================================

router.post("/analyze", async (req, res) => {

    try {

        const userId = req.session.user.id;

        const {
            configurationId
        } = req.body;


        // ==========================================
        // CHECK CONFIGURATION
        // ==========================================

        if (!configurationId) {

            return res.status(400).send(
                "Configuration is required."
            );
        }


        // ==========================================
        // FIND CONFIGURATION
        // ==========================================

        const configuration =
            await Configuration
                .findById(configurationId)
                .populate("device");


        if (!configuration) {

            return res.status(404).send(
                "Configuration not found."
            );
        }


        // ==========================================
        // OWNERSHIP CHECK
        // ==========================================

        if (
            !configuration.device ||
            !configuration.device.user ||
            configuration.device.user.toString() !==
            userId.toString()
        ) {

            return res.status(403).send(
                "Access denied."
            );
        }


        // ==========================================
        // RUN EXPOSURE ANALYSIS
        // ==========================================

        const result =
            await runExposureAnalysis(
                configuration.filePath
            );


        // ==========================================
        // RELOAD USER CONFIGURATIONS
        // ==========================================

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


        // ==========================================
        // RENDER RESULT
        // ==========================================

        res.render(
            "pages/exposureAnalysis",
            {

                configurations,

                result,

                selectedConfiguration:
                    configuration

            }
        );


    } catch (error) {

        console.error(
            "Exposure analysis error:",
            error
        );

        res.status(500).send(
            "Exposure analysis failed: " +
            error.message
        );
    }
});


module.exports = router;