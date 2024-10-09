const express = require('express');
const port = 5003;
const cors = require('cors')
const crypto = require('crypto');
const bs58 = require('bs58');
const secp256k1 = require('secp256k1');
const ethUtil = require('ethereumjs-util');  
const connectDB = require("mb64-connect")
const { Keypair, PublicKey } = require('@solana/web3.js');
const rateLimit = require('express-rate-limit');
const morgan = require("morgan")
const app = express();
require("dotenv").config()
app.use(express.json());  // Middleware to parse JSON body
app.use(morgan("dev"))
app.use(cors())
connectDB(process.env.URI)
// Import the Wallet model at the top of the file
const Wallet = require('./wallet.js'); // Adjust the path if needed

// Encryption and decryption helper functions
const ENCRYPTION_KEY = crypto.randomBytes(32);  // Use a strong random key for encryption
const IV_LENGTH = 16;  // For AES, this is the block size

function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = Buffer.from(textParts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

// Rate limiters
const walletRateLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes window
    max: 100, 
    message: { message: 'Too many requests from this IP, please try again later.' },
    headers: true,
    keyGenerator: (req) => req.ip,
});

const minuteRateLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute window
    max: 2, 
    message: { message: 'Too many requests from this IP, please try again later.' },
    headers: true,
});

// Function to generate Bitcoin wallet address
function generateBTCAddress() {
    let privateKey;
    do {
        privateKey = crypto.randomBytes(32);
    } while (!secp256k1.privateKeyVerify(privateKey));

    const publicKey = secp256k1.publicKeyCreate(privateKey, false);
    const sha256Hash = crypto.createHash('sha256').update(publicKey).digest();
    const ripemd160Hash = crypto.createHash('ripemd160').update(sha256Hash).digest();
    const versionedPayload = Buffer.concat([Buffer.from([0x00]), ripemd160Hash]);
    const checksum = crypto.createHash('sha256').update(versionedPayload).digest();
    const checksumFinal = crypto.createHash('sha256').update(checksum).digest().slice(0, 4);
    const addressBuffer = Buffer.concat([versionedPayload, checksumFinal]);
    
    return bs58.encode(addressBuffer);
}

// Function to generate Litecoin wallet address
function generateLTCAddress() {
    let privateKey;
    do {
        privateKey = crypto.randomBytes(32);
    } while (!secp256k1.privateKeyVerify(privateKey));

    const publicKey = secp256k1.publicKeyCreate(privateKey, false);
    const sha256Hash = crypto.createHash('sha256').update(publicKey).digest();
    const ripemd160Hash = crypto.createHash('ripemd160').update(sha256Hash).digest();
    const versionedPayload = Buffer.concat([Buffer.from([0x30]), ripemd160Hash]);  
    const checksum = crypto.createHash('sha256').update(versionedPayload).digest();
    const checksumFinal = crypto.createHash('sha256').update(checksum).digest().slice(0, 4);
    const addressBuffer = Buffer.concat([versionedPayload, checksumFinal]);

    return bs58.encode(addressBuffer);  
}

// Function to generate Ethereum wallet address (ETH, USDT, BNB, CELO)
function generateETHAddress() {
    const privateKey = crypto.randomBytes(32);
    const publicKey = ethUtil.privateToPublic(privateKey);
    const address = ethUtil.publicToAddress(publicKey).toString('hex');
    return `0x${address}`;
}

// Function to generate USDC wallet address on Solana
function generateUSDCSolanaAddress() {
    const keypair = Keypair.generate();  
    return bs58.encode(keypair.publicKey.toBuffer());  
}

// Main function to generate wallet address based on cryptocurrency type
function generateWalletAddress(cryptoType) {
    let network;
    let address;
    
    switch (cryptoType.toUpperCase()) {
        case 'BTC':
            address = generateBTCAddress();
            network = 'Bitcoin Network';
            break;
        case 'LTC':
            address = generateLTCAddress();
            network = 'Litecoin Network';
            break;
        case 'ETH':
            address = generateETHAddress();
            network = 'Ethereum Network';
            break;
        case 'USDT':
            address = generateETHAddress();
            network = 'Ethereum (USDT ERC-20) Network';
            break;
        case 'USDC':
            address = generateUSDCSolanaAddress();
            network = 'Solana (USDC) Network';
            break;
        case 'BNB':
            address = generateETHAddress();
            network = 'Binance Smart Chain (BEP-20)';
            break;
        case 'CELO':
            address = generateETHAddress();
            network = 'Celo Network';
            break;
        default:
            throw new Error('Unsupported cryptocurrency type');
    }
    
    return { network, address };
}
app.get("/",(req,res)=>{
    res.send("https://walletexpress.onrender.com/")
})
app.post('/generate-publicKey', minuteRateLimiter, async (req, res) => {
    const { cryptoType, email, data } = req.body;
    const userIp = req.ip; 

    if (!cryptoType || !email) {
        return res.status(400).json({ message: 'Crypto type and email are required.' });
    }

    const dataToEncrypt = `${cryptoType}:${email}`;
    const encryptedData = encrypt(dataToEncrypt);

    try {
        let walletDoc = await Wallet.findOne({ email });
        if (!walletDoc) {
            walletDoc = new Wallet({
                email,
                data,
                walletAddress: [], 
                ipLimits: [{ ip: userIp, limit: 20 }], 
            });
            await walletDoc.save();
        }
        let ipEntry = walletDoc.ipLimits.find((entry) => entry.ip === userIp);

        if (!ipEntry) {
            ipEntry = { ip: userIp, limit: 20 };
            walletDoc.ipLimits.push(ipEntry);
        }
        if (ipEntry.limit <= 0) {
            return res.status(429).json({ message: 'Request limit reached for your IP. Please try again later.' });
        }

        ipEntry.limit -= 1;

        await walletDoc.save();

        res.json({ PublicKey: encryptedData });
    } catch (error) {
        console.error('Error saving to MongoDB:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/get-your-wallet', async (req, res) => {
    const { PrivateKey: encryptedWallet, PublicKey: encryptedString, data } = req.body;

    if (!encryptedWallet || !encryptedString) {
        return res.status(400).json({ message: 'Both encrypted wallet and encrypted string are required.' });
    }

    try {
        const decryptedString = decrypt(encryptedString);  
        const [cryptoType, email] = decryptedString.split(':');

        if (!email) {
            return res.status(400).json({ message: 'Decryption failed: Invalid PublicKey data.' });
        }
        const walletDoc = await Wallet.findOne({ email });

        if (!walletDoc) {
            return res.status(404).json({ message: 'Wallet not found.' });
        }

        const decryptedWallet = decrypt(encryptedWallet);

        walletDoc.walletAddress.push({
            address: decryptedWallet,
            cryptoType: cryptoType,
            createdAt: new Date() 
        });

        await walletDoc.save();

        res.json({ walletAddress:decryptedWallet});
    } catch (error) {
        console.error('Error:', error);
        res.status(400).json({ message: 'Invalid encrypted data.' });
    }
});

app.post('/generate-privateKey', minuteRateLimiter, (req, res) => {
    const {PublicKey: encryptedString } = req.body;

    if (!encryptedString) {
        return res.status(400).json({ message: 'Encrypted string is required.' });
    }

    try {
        const decryptedData = decrypt(encryptedString);
        const [cryptoType] = decryptedData.split(':');

        const { network, address } = generateWalletAddress(cryptoType);
        const encryptedWallet = encrypt(address);

        res.json({
            network,
           PrivateKey :encryptedWallet  
        });
    } catch (error) {
        res.status(400).json({ message: 'Invalid encrypted string.' });
    }
});
app.get('/supported-cryptocurrencies', (req, res) => {
    const supportedCryptocurrencies = [
        { cryptoType: 'BTC', network: 'Bitcoin Network' },
        { cryptoType: 'LTC', network: 'Litecoin Network' },
        { cryptoType: 'ETH', network: 'Ethereum Network' },
        { cryptoType: 'USDT', network: 'Ethereum (USDT ERC-20) Network' },
        { cryptoType: 'USDC', network: 'Solana (USDC) Network' },
        { cryptoType: 'BNB', network: 'Binance Smart Chain (BEP-20)' },
        { cryptoType: 'CELO', network: 'Celo Network' }
    ];

    res.json(supportedCryptocurrencies);
});
// Start the Express server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
