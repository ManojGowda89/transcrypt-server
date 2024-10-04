const express = require('express');
const port = 5003;
const cors = require('cors')
const crypto = require('crypto');
const bs58 = require('bs58');
const secp256k1 = require('secp256k1');
const ethUtil = require('ethereumjs-util');  
const { Keypair, PublicKey } = require('@solana/web3.js');
const rateLimit = require('express-rate-limit');
const morgan = require("morgan")
const app = express();
app.use(express.json());  // Middleware to parse JSON body
app.use(morgan("dev"))
app.use(cors())
 
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
    max: 8, 
    message: { message: 'Too many requests from this IP, please try again later.' },
    headers: true,
    keyGenerator: (req) => req.ip,
});

const minuteRateLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute window
    max: 100, 
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

// Route 1: Accept crypto and email, return encrypted string
app.post('/generate-publicKey',walletRateLimiter,minuteRateLimiter, (req, res) => {
    const { cryptoType, email } = req.body;
    
    if (!cryptoType || !email) {
        return res.status(400).json({ message: 'Crypto type and email are required.' });
    }

    const dataToEncrypt = `${cryptoType}:${email}`;
    const encryptedData = encrypt(dataToEncrypt);

    res.json({ PublicKey: encryptedData });
});

// Route 2: Accept encrypted string, decrypt it, generate wallet, and return encrypted wallet
app.post('/generate-privateKey', walletRateLimiter, minuteRateLimiter, (req, res) => {
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

// Route 3: Decrypt wallet address
app.post('/get-your-wallet', (req, res) => {
    const {PrivateKey: encryptedWallet, PublicKey:encryptedString } = req.body;

    if (!encryptedWallet || !encryptedString) {
        return res.status(400).json({ message: 'Both encrypted wallet and encrypted string are required.' });
    }

    try {
        decrypt(encryptedString);  

        const decryptedWallet = decrypt(encryptedWallet);

        res.json({ walletAddress: decryptedWallet });
    } catch (error) {
        res.status(400).json({ message: 'Invalid encrypted data.' });
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
