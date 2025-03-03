const net = require('net');
const crypto = require('crypto');
import { addMessageToHistory } from './uiChatInteract.js';
import { findIdByUserId } from './database.js';
import { hexToUint8Array, tsToUint8Array, intToUint8Array } from './convertions.js'
import { decryptMessage, encryptData } from './encryption.js';
import { connectSocks5 } from './tor.js';

export async function establishTCPConnection() {
    if (client) {
        client.destroy();
    }

    try {
        await getAssignedNode(HOST, PORT);
        //client = await connectSocks5('127.0.0.1', 9050, HOST, PORT)
        client = net.createConnection({ host: HOST, port: PORT }, () => console.log('Connected to server!'));
        connectAsBytes();
        

        let buffer = Buffer.alloc(0);

        client.on("data", async (chunk) => {
            buffer = Buffer.concat([buffer, chunk]);
            const packet_size = buffer.readUInt16LE(1);
            if (buffer.length < packet_size) {
                return;
            }
        
            if (buffer[0] === 0x02) {
                handleKyber(buffer);
            } 
            else if (buffer[0] === 0x03) {
                handleCypher(buffer);
            } 
            else if (buffer[0] === 0x04) {
                handleMessage(buffer);
            }
            else {
                buffer = Buffer.alloc(0);
            }
            const remainingData = buffer.slice(packet_size);
            buffer = remainingData;
        });

        client.on("close", () => {
            console.log("Connection closed");
            client = null;
        });

        client.on("error", (err) => {
            console.error("Connection error:", err);
            client = null;
        });
    } catch (err) {
        console.error("Error connecting to node:", err);
    }
}

async function handleCypher(buffer) {
    const hash = crypto.createHash('sha256');
    const signatureLength = buffer.readUInt16LE(3);
    hash.update(buffer.slice(signatureLength + 5, signatureLength + 5 + 1952));
    const srcId = hash.digest('hex');

    if (!allDestIds.includes(srcId)) { 
        let invites = JSON.parse(localStorage.getItem('invites')) || {};
        invites[srcId] = Date.now();
        localStorage.setItem('invites', JSON.stringify(invites));
        return
    }
    sharedSecret[srcId] = await kyberInstance.decap(buffer.slice(signatureLength + 32 + 5 + 1952 + 8, signatureLength + 32 + 5 + 1952 + 8 + 1568), kyberPrivateKey);
    await saveSharedSecret(sharedSecret[srcId], srcId);
    
}

async function handleKyber(buffer) {
    const hash = crypto.createHash('sha256');
    const signatureLength = buffer.readUInt16LE(3);
    hash.update(buffer.slice(signatureLength + 5, signatureLength + 5 + 1952));
    const srcId = hash.digest('hex');
    if (!allDestIds.includes(srcId)) { 
        let invites = JSON.parse(localStorage.getItem('invites')) || {};
        invites[srcId] = Date.now();
        localStorage.setItem('invites', JSON.stringify(invites));
        return
    }
    const [ct, sharedSecretTemp] = await kyberInstance.encap(buffer.slice(signatureLength + 32 + 5 + 1952 + 8, signatureLength + 32 + 5 + 1952 + 8 + 1568));
    sharedSecret[srcId] = await sharedSecretTemp;
    sendCypher(ct, srcId);
}

async function handleMessage(buffer) {
    const hash = crypto.createHash('sha256');
    const signatureLength = buffer.readUInt16LE(3);
    hash.update(buffer.slice(signatureLength + 5, signatureLength + 5 + 1952));
    const srcId = hash.digest('hex');
    const secret = sharedSecret[srcId];
    const encryptedMessage = buffer.slice(signatureLength + 32 + 5 + 1952 + 8, buffer.length);
    const decryptedMessage = await decryptMessage(encryptedMessage, secret,"message");
    const decoder = new TextDecoder();
    const message = decoder.decode(decryptedMessage);
    const id = await findIdByUserId(srcId);
    addMessageToHistory(message, "user", id, srcId);
}

async function saveSharedSecret(sharedSecret, dstId) {
    let sharedSecrets = JSON.parse(localStorage.getItem('shared_secrets')) || {};
    sharedSecrets[dstId] = await encryptData(sharedSecret, password);
    localStorage.setItem('shared_secrets', JSON.stringify(sharedSecrets));
}

function connectAsBytes() {
    const time = Date.now();
    const publicKey = dilithiumKeyPair.pubkey;
    const prefix = new Uint8Array([0x01, 0x00, 0x00]);
    const bytesTs = tsToUint8Array(time);
    
    const dataToSign = new Uint8Array(publicKey.length + bytesTs.length);
    dataToSign.set(publicKey, 0);
    dataToSign.set(bytesTs, publicKey.length);
    
    const signature = dilithiumKeyPair.sign(dataToSign);
    const signatureLength = intToUint8Array(signature.length);

    const headers = new Uint8Array(prefix.length + signatureLength.length);
    headers.set(prefix, 0);
    headers.set(signatureLength, prefix.length);

    const data = new Uint8Array(signature.length + dataToSign.length);
    data.set(signature, 0);
    data.set(dataToSign, signature.length);

    const finalData = new Uint8Array(headers.length + data.length);
    finalData.set(headers, 0);
    finalData.set(data, headers.length);
    finalData.set(intToUint8Array(finalData.length), 1);

    client.write(finalData);
}

export function sendKyberKey(kyberPublicKey) {
    const time = Date.now();
    const publicKey = dilithiumKeyPair.pubkey;

    const prefix = new Uint8Array([0x02, 0x00, 0x00]);
    const bytesTs = tsToUint8Array(time);
    const destId = hexToUint8Array(currentChatDestUserId);

    const dataToSign = new Uint8Array(publicKey.length + kyberPublicKey.length + destId.length + bytesTs.length);
    dataToSign.set(publicKey, 0);
    dataToSign.set(destId, publicKey.length);
    dataToSign.set(bytesTs, publicKey.length + destId.length);
    dataToSign.set(kyberPublicKey, publicKey.length + destId.length + bytesTs.length);

    const signature = dilithiumKeyPair.sign(dataToSign);
    const signatureLength = intToUint8Array(signature.length);

    const headers = new Uint8Array(prefix.length + signatureLength.length);
    headers.set(prefix, 0);
    headers.set(signatureLength, prefix.length);

    const data = new Uint8Array(signature.length + dataToSign.length);
    data.set(signature, 0);
    data.set(dataToSign, signature.length);

    const finalData = new Uint8Array(headers.length + data.length);
    finalData.set(headers, 0);
    finalData.set(data, headers.length);
    finalData.set(intToUint8Array(finalData.length), 1);

    client.write(finalData);
}

export function sendCypher(ct, dstIdHex) {
    const time = Date.now();
    const dstId = hexToUint8Array(dstIdHex);
    const publicKey = dilithiumKeyPair.pubkey;
    const prefix = new Uint8Array([0x03, 0x00, 0x00]);
    const bytesTs = tsToUint8Array(time);

    const dataToSign = new Uint8Array(publicKey.length + dstId.length + bytesTs.length + ct.length);
    dataToSign.set(publicKey, 0);
    dataToSign.set(dstId, publicKey.length);
    dataToSign.set(bytesTs, publicKey.length + dstId.length);
    dataToSign.set(ct, publicKey.length + dstId.length + bytesTs.length);

    const signature = dilithiumKeyPair.sign(dataToSign);
    const signatureLength = intToUint8Array(signature.length);

    const headers = new Uint8Array(prefix.length + signatureLength.length);
    headers.set(prefix, 0);
    headers.set(signatureLength, prefix.length);

    const data = new Uint8Array(signature.length + dataToSign.length);
    data.set(signature, 0);
    data.set(dataToSign, signature.length);

    const finalData = new Uint8Array(headers.length + data.length);
    finalData.set(headers, 0);
    finalData.set(data, headers.length);
    finalData.set(intToUint8Array(finalData.length), 1);

    client.write(finalData);
}

export function emitMessage(msg) {
    const time = Date.now();
    const dstId = hexToUint8Array(currentChatDestUserId);
    const publicKey = dilithiumKeyPair.pubkey;
    const prefix = new Uint8Array([0x04, 0x00, 0x00]);
    const bytesTs = tsToUint8Array(time);

    const dataToSign = new Uint8Array(publicKey.length + dstId.length + bytesTs.length + msg.length);
    dataToSign.set(publicKey, 0);
    dataToSign.set(dstId, publicKey.length);
    dataToSign.set(bytesTs, publicKey.length + dstId.length);
    dataToSign.set(msg, publicKey.length + dstId.length + bytesTs.length);

    const signature = dilithiumKeyPair.sign(dataToSign);
    const signatureLength = intToUint8Array(signature.length);

    const headers = new Uint8Array(prefix.length + signatureLength.length);
    headers.set(prefix, 0);
    headers.set(signatureLength, prefix.length);

    const data = new Uint8Array(signature.length + dataToSign.length);
    data.set(signature, 0);
    data.set(dataToSign, signature.length);

    const finalData = new Uint8Array(headers.length + data.length);
    finalData.set(headers, 0);
    finalData.set(data, headers.length);
    finalData.set(intToUint8Array(finalData.length), 1);

    client.write(finalData);
}

export async function getAssignedNode(ip, port) {
    return new Promise((resolve, reject) => {
        client = net.createConnection({ host: ip, port: port }, () => {
            console.log('Connected to server!');
        });

        client.on("data", async (buffer) => {

            const decoder = new TextDecoder('utf-8');
            const response = decoder.decode(buffer.slice(3));
            const parts = response.split(' ');

            let ips = parts.map(part => part.trim()).filter(part => part.length > 0);
            HOST = ips[0];
            console.log('Primary node:', HOST);
            console.log("Fallback nodes:", ips.slice(1));

            resolve();
        });

        client.on("error", (err) => {
            reject(err);
        });

        const time = Date.now();
        const publicKey = dilithiumKeyPair.pubkey;
        const prefix = new Uint8Array([0x0a, 0x00, 0x00]);
        const bytesTs = tsToUint8Array(time);

        const dataToSign = new Uint8Array(publicKey.length + bytesTs.length);
        dataToSign.set(publicKey, 0);
        dataToSign.set(bytesTs, publicKey.length);

        const signature = dilithiumKeyPair.sign(dataToSign);
        const signatureLength = intToUint8Array(signature.length);

        const headers = new Uint8Array(prefix.length + signatureLength.length);
        headers.set(prefix, 0);
        headers.set(signatureLength, prefix.length);

        const data = new Uint8Array(signature.length + dataToSign.length);
        data.set(signature, 0);
        data.set(dataToSign, signature.length);

        const finalData = new Uint8Array(headers.length + data.length);
        finalData.set(headers, 0);
        finalData.set(data, headers.length);
        finalData.set(intToUint8Array(finalData.length), 1);

        client.write(finalData);
    });
}
