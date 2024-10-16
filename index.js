const express = require('express');
const port = 5003;
const cors = require('cors');
const morgan = require('morgan');
const connectDB = require("mb64-connect");
const Wallet = require('./models/wallet.js');  // Adjust the path if necessary
const CryptoJS = require("crypto-js")
// Import functions
const { encrypt, decrypt } = require('./functions/encryption');
const { generateWalletAddress } = require('./functions/walletGeneration');
// const { minuteRateLimiter } = require('./functions/rateLimiter');

const app = express();
require("dotenv").config();

app.use(express.json());  // Middleware to parse JSON body
app.use(morgan("dev"));
app.use(cors());
connectDB(process.env.URI);

app.get("/",(req,res)=>{
    res.send("https://walletexpress.onrender.com/")
})

app.post('/generate-publicKey', async (req, res) => {
    const { cryptoType, email, apiKey,ip:userIp } = req.body;
    if (!cryptoType || !email) {
        return res.status(400).json({ message: 'Crypto type and email are required.' });
    }

    const dataToEncrypt = `${cryptoType}:${email}`;
    const encryptedData = encrypt(dataToEncrypt);

    try {
        let walletDoc = await Wallet.findOne({ email });
        
        // If the wallet doesn't exist, create it
        if (!walletDoc) {
            walletDoc = new Wallet({
                email,
                userIp,
                apiKey: Math.random().toString(36).substring(2, 15),
                apiCreationDate:new Date,
                walletAddress: [],
                ipLimits: [{ ip: userIp, limit: 20 }],
            });
            await walletDoc.save();
        }

        const currentDate = new Date();
        const oneMonthAgo = new Date(currentDate.setMonth(currentDate.getMonth() - 1));
        
        if (walletDoc.apiCreationDate && walletDoc.apiCreationDate < oneMonthAgo) {
            walletDoc.apiKey = Math.random().toString(36).substring(2, 15);
            walletDoc.apiCreationDate = new Date(); 
            await walletDoc.save();
        }

        // Check if the provided API key matches the one in the document
        if (walletDoc.apiKey && walletDoc.apiKey === apiKey) {
            return res.json({
                PublicKey: encryptedData,
                message: 'Public key generated successfully for paid user (limit bypassed).',
            });
        }

        // Handle rate-limiting logic based on the user's IP
        let ipEntry = walletDoc.ipLimits.find((entry) => entry.ip === userIp);

        if (!ipEntry) {
            ipEntry = { ip: userIp, limit: 20 }; // Default limit
            walletDoc.ipLimits.push(ipEntry);
        }

        if (ipEntry.limit <= 0) {
            return res.status(429).json({ message: 'Request limit reached for your IP. Please try again later.' });
        }

        ipEntry.limit -= 1; // Decrease the limit

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
            data,
            createdAt: new Date() 
        });

        await walletDoc.save();

        res.json({ walletAddress:decryptedWallet});
    } catch (error) {
        console.error('Error:', error);
        res.status(400).json({ message: 'Invalid encrypted data.' });
    }
});

app.post('/generate-privateKey', (req, res) => {
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


app.post('/decrypt-data', (req, res) => {
    const { data,Key } = req.body; 
    const secretKey = process.env.VITE_API_KEY||Key;
    if (!data) {
      return res.status(400).json({
        success: false,
        message: 'No encrypted data provided',
      });
    }
  
    try {
      const decryptedData = CryptoJS.AES.decrypt(data, secretKey).toString(CryptoJS.enc.Utf8);
      const parsedData = JSON.parse(decryptedData);
      res.json({
        success: true,
        decryptedData: parsedData,
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Failed to decrypt data',
        error: error.message,
      });
    }
  });
  

// Listen on port
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
