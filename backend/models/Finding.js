const mongoose = require("mongoose");

const findingSchema = new mongoose.Schema(
    {
        audit: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Audit",
            required: true
        },

        device: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Device",
            required: true
        },

        title: {
            type: String,
            required: true
        },

        category: {
            type: String,
            enum: [
                "Remote Access",
                "Authentication",
                "Encryption",
                "Access Control",
                "Configuration",
                "Other"
            ],
            default: "Other"
        },

        severity: {
            type: String,
            enum: ["Critical", "High", "Medium", "Low", "Informational"],
            required: true
        },

        description: {
            type: String,
            required: true
        },

        detectedConfig: {
            type: String,
            default: null
        },

        recommendedFix: {
            type: String,
            default: null
        },

        aiExplanation: {
            type: String,
            default: null
        },

        status: {
            type: String,
            enum: ["Open", "Resolved", "Ignored"],
            default: "Open"
        },

        resolvedAt: {
            type: Date,
            default: null
        }
    },
    {
        timestamps: true
    }
);

module.exports = mongoose.model("Finding", findingSchema);