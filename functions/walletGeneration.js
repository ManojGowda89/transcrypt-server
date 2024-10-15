const crypto = require('crypto');
const bs58 = require('bs58');
const secp256k1 = require('secp256k1');
const ethUtil = require('ethereumjs-util');  
const { Keypair } = require('@solana/web3.js');

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

module.exports = { generateWalletAddress };
