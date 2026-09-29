const mongoose = require("mongoose");

const deviceSchema = new mongoose.Schema(
    {
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true
        },

        deviceName: {
            type: String,
            required: true,
            trim: true
        },

        vendor: {
            type: String,
            required: true,
            enum: ["Cisco", "Juniper", "Fortinet", "Unknown"]
        },

        deviceType: {
            type: String,
            default: "Network Device"
        },

        ipAddress: {
            type: String,
            default: null
        },

        status: {
            type: String,
            enum: ["Active", "Inactive"],
            default: "Active"
        },

        lastAudit: {
            type: Date,
            default: null
        },

        securityScore: {
            type: Number,
            default: 0
        }
    },
    {
        timestamps: true
    }
);

module.exports = mongoose.model("Device", deviceSchema);