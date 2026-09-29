const express = require("express");

const {
    analyzeUnknownConfiguration
} = require("../services/aiTrainingService");

const router = express.Router();


// =====================================
// AI TRAINING PAGE
// =====================================

router.get("/", (req, res) => {

    res.render(
        "pages/aiTraining",
        {
            result: null
        }
    );

});


// =====================================
// ANALYZE CONFIGURATION
// =====================================

router.post("/analyze", (req, res) => {

    try {

        const {
            configLine,
            vendor
        } = req.body;


        if (!configLine) {

            return res.status(400).send(
                "Configuration is required."
            );

        }


        const result =
            analyzeUnknownConfiguration(
                configLine,
                vendor
            );


        res.render(
            "pages/aiTraining",
            {
                result
            }
        );


    } catch (error) {

        console.error(
            "AI training analysis error:",
            error
        );


        res.status(500).send(
            "AI configuration analysis failed: " +
            error.message
        );

    }

});


module.exports = router;