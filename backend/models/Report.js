const mongoose = require("mongoose");

const reportSchema = new mongoose.Schema(
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

        reportName: {
            type: String,
            required: true
        },

        complianceScore: {
            type: Number,
            min: 0,
            max: 100,
            default: 0
        },

        totalFindings: {
            type: Number,
            default: 0
        },

        reportPath: {
            type: String,
            default: null
        },

        generatedAt: {
            type: Date,
            default: Date.now
        }
    },
    {
        timestamps: true
    }
);

module.exports = mongoose.model(
    "Report",
    reportSchema
);