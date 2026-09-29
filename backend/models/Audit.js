const mongoose = require("mongoose");

const auditSchema = new mongoose.Schema(
    {
        device: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Device",
            required: true
        },

        configuration: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Configuration",
            required: true
        },

        vendor: {
            type: String,
            enum: ["Cisco", "Juniper", "Fortinet", "Unknown"],
            required: true
        },

        status: {
            type: String,
            enum: ["Pending", "Running", "Completed", "Failed"],
            default: "Pending"
        },

        complianceScore: {
            type: Number,
            min: 0,
            max: 100,
            default: 0
        },

        totalChecks: {
            type: Number,
            default: 0
        },

        passedChecks: {
            type: Number,
            default: 0
        },

        failedChecks: {
            type: Number,
            default: 0
        },

        criticalFindings: {
            type: Number,
            default: 0
        },

        highFindings: {
            type: Number,
            default: 0
        },

        mediumFindings: {
            type: Number,
            default: 0
        },

        lowFindings: {
            type: Number,
            default: 0
        },

        startedAt: {
            type: Date,
            default: null
        },

        completedAt: {
            type: Date,
            default: null
        }
    },
    {
        timestamps: true
    }
);

module.exports = mongoose.model("Audit", auditSchema);