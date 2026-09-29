const mongoose = require("mongoose");

const configurationSchema = new mongoose.Schema(
    {
        device: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Device",
            required: true
        },

        fileName: {
            type: String,
            required: true
        },

        vendor: {
            type: String,
            enum: ["Cisco", "Juniper", "Fortinet", "Unknown"],
            required: true
        },

        filePath: {
            type: String,
            required: true
        },

        configVersion: {
            type: String,
            default: "1.0"
        },

        uploadedAt: {
            type: Date,
            default: Date.now
        },

        status: {
            type: String,
            enum: ["Uploaded", "Analyzed", "Failed"],
            default: "Uploaded"
        }
    },
    {
        timestamps: true
    }
);

module.exports = mongoose.model("Configuration", configurationSchema);