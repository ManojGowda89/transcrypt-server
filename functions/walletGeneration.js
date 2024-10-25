const crypto = require('crypto');
const bs58 = require('bs58');
const secp256k1 = require('secp256k1');
const ethUtil = require('ethereumjs-util');
const { Keypair } = require('@solana/web3.js');

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

function generateETHAddress() {
    const privateKey = crypto.randomBytes(32);
    const publicKey = ethUtil.privateToPublic(privateKey);
    const address = ethUtil.publicToAddress(publicKey).toString('hex');
    return `0x${address}`;
}


function generateUSDCSolanaAddress() {
    const keypair = Keypair.generate();
    return bs58.encode(keypair.publicKey.toBuffer());
}


function generateWalletAddress(cryptoType) {
    let network;
    let address;

    switch (cryptoType.toUpperCase()) {
        case 'BTC':
        case "BSV" :   
            address = generateBTCAddress();
            network = 'Bitcoin Network';
            break;
        case 'LTC':
        case 'DOGE': 
            address = generateLTCAddress();
            network = 'Litecoin Network';
            break;
        case 'ETH':
        case 'ETH1':
        case 'ETH2':
        case 'USDT':
        case 'CELO':
        case 'WLD':
        case 'BNB':
        case "USDC1":
        case "USDT1":
            address = generateETHAddress();
            network = 'Etheriem Network';
            break;
        case 'USDC':
        case "USDT-SOL":
        case "SOL":
            address = generateUSDCSolanaAddress();
            network = 'Solana Network';
            break;
        default:
            throw new Error('Unsupported cryptocurrency type');
    }

    return { network, address };
}

module.exports = { generateWalletAddress };
