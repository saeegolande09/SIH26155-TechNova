const express = require("express");

const Finding = require("../models/Finding");
const Device = require("../models/Device");

const {
    generateAIExplanation
} = require("../services/aiService");

const router = express.Router();


// ==========================================
// FINDINGS PAGE
// ==========================================

router.get("/", async (req, res) => {

    try {

        // Findings listing is handled by
        // the Risk Prioritization page.
        // Redirect there so /findings works.

        return res.redirect("/risk");

    } catch (error) {

        console.error(
            "Findings page error:",
            error
        );

        res.status(500).send(
            "Failed to load findings."
        );
    }
});


// ==========================================
// FINDING DETAILS
// ==========================================

router.get("/:id", async (req, res) => {

    try {

        const userId = req.session.user.id;


        // ==========================================
        // GET FINDING
        // ==========================================

        const finding =
            await Finding.findById(req.params.id);

        if (!finding) {
            return res.status(404).send(
                "Finding not found."
            );
        }


        // ==========================================
        // GET DEVICE
        // ==========================================

        const device =
            await Device.findById(finding.device);

        if (!device) {
            return res.status(404).send(
                "Device not found."
            );
        }


        // ==========================================
        // OWNERSHIP CHECK
        // ==========================================

        if (
            !device.user ||
            device.user.toString() !==
            userId.toString()
        ) {
            return res.status(403).send(
                "Access denied."
            );
        }


        // ==========================================
        // AI EXPLANATION
        // ==========================================

        const aiResult =
            generateAIExplanation(finding);


        // ==========================================
        // RENDER FINDING DETAILS
        // ==========================================

        res.render("pages/findingDetails", {

            finding,

            device,

            aiResult

        });


    } catch (error) {

        console.error(
            "Finding details error:",
            error
        );

        res.status(500).send(
            "Failed to load finding details."
        );
    }
});


module.exports = router;