const mongoose = require('mongoose');

const WalletSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true,
    },
    apiKey: {
        type: String,
    },
    apiCreationDate: {
        type: Date,
        default: Date.now, // Set the default to the current date when the document is created
    },
    userIp: {
        type: String,
        required: true,
    },
    walletAddress: [
        {
            address: {
                type: String,
                required: true,
            },
            cryptoType: {
                type: String,
                required: true,
            },
            data: {
                type: Object,
                required: true,
            },
            createdAt: {
                type: Date,
                default: Date.now,
            },
        },
    ],
    ipLimits: [
        {
            ip: {
                type: String,
                // required: true,
            },
            limit: {
                type: Number,
                default: 20, // Default limit for each IP
            },
        },
    ],
}, { timestamps: true });

const Wallet = mongoose.model('Wallet', WalletSchema);
module.exports = Wallet;
