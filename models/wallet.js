const connectDB= require("mb64-connect");

const walletSchema = {
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
        default: Date.now,
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
                required: true,
            },
            limit: {
                type: Number,
                default: 20,
            },
        },
    ],
};

const Wallet = connectDB.validation("Wallet", walletSchema, true);

module.exports = Wallet;