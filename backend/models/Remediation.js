const mongoose = require("mongoose");

const remediationSchema = new mongoose.Schema(
    {
        finding: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Finding",
            required: true
        },

        recommendedFix: {
            type: String,
            required: true
        },

        fixType: {
            type: String,
            enum: ["Manual", "Automated", "AI Suggested"],
            default: "Manual"
        },

        commands: {
            type: [String],
            default: []
        },

        status: {
            type: String,
            enum: ["Pending", "Applied", "Verified", "Failed"],
            default: "Pending"
        },

        verifiedAt: {
            type: Date,
            default: null
        }
    },
    {
        timestamps: true
    }
);

module.exports = mongoose.model("Remediation", remediationSchema);
