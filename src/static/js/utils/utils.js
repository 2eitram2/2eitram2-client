import {openModal} from './uiChatInteract.js'
import {decryptMessage} from './encryption.js';
import {findUserIdById, removeChatFromDb} from './database.js';

const crypto = require('crypto');

export async function setup() {
    const hash = crypto.createHash('sha256');
    const data = Buffer.from(dilithiumKeyPair.pubkey);
    hash.update(data);
    const hashedData = hash.digest('hex');
    const sessionUserId = hashedData;
    document.getElementById("userId").innerHTML = `<h2>Your User ID:</h2><pre>${sessionUserId}</pre>`;
}

export function clearChat() {

    const messagesContainer = document.querySelector('.messages');
    while (messagesContainer.firstChild) {

        messagesContainer.removeChild(messagesContainer.firstChild);
    }
}

export async function removeChat() {

    const button = document.querySelector(`.sidebar-button[data-chatid="${currentChatNum}"]`);
    findUserIdById(currentChatNum).then(function (userId) {
        let sharedSecrets = JSON.parse(localStorage.getItem('shared_secrets')) || {};
        delete sharedSecrets[userId];
        localStorage.setItem('shared_secrets', JSON.stringify(sharedSecrets));
    });
    
    await removeChatFromDb();
    
    clearChat();
    if (button) {
        button.remove();
    } else {
        console.log("Button not found");
    }
}

export function getSharedSecrets() {

    const sharedSecrets = JSON.parse(localStorage.getItem('shared_secrets')) || {};
    return sharedSecrets
}

export async function decryptSharedSecrets() {

    const shared_secrets = getSharedSecrets();
    for (const user_id in shared_secrets) {
        const decryptedSecret = await decryptMessage(shared_secrets[user_id], password, "file");        
        sharedSecret[user_id] =  decryptedSecret;
    }
}

export function stringToUint8Array(plaintext) {
    const encoder = new TextEncoder();
    return encoder.encode(plaintext);
}

export function uint8ArrayToString(array) {
    const decoder = new TextDecoder();
    return decoder.decode(array);
}

export function convertToHex(key) {

    let hex = '';

    for (let i = 0; i < key.length; i++) {
      hex += key[i].toString(16).padStart(2, '0');
    }

    return hex;
}

export function hexToUint8Array(hex) {

  const bytes = new Uint8Array(hex.length / 2);

  for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }

  return bytes;
}

export function loadInvites() {
    document.querySelectorAll('.sidebar-button').forEach((element) => {
        if (areChatsDisplayed) {
            element.style.display = 'none';
        } else {
            element.style.display = 'block';
        }
    });

    document.querySelectorAll('.invite-button').forEach((element) => {
        if (areChatsDisplayed) {
            element.style.display = 'block';
        } else {
            element.style.display = 'none';
        }
    });

    if (areChatsDisplayed) {
        let invites = JSON.parse(localStorage.getItem('invites')) || {};

        const sidebar = document.querySelector('.sidebar');
        if (!sidebar) {
            console.error('Sidebar container not found!');
            return;
        }

        sidebar.querySelectorAll('.invite-button').forEach(button => button.remove());

        for (const invite in invites) {
            const newButton = document.createElement('button');
            newButton.classList.add('invite-button');
            newButton.textContent = `Invite from ${invite}`;
            newButton.dataset.userId = invite;
            newButton.onclick = async () => {
                document.getElementById("user_id").value = invite;
                openModal();
            };
            sidebar.appendChild(newButton);
        }
    }

    areChatsDisplayed = !areChatsDisplayed;
}

export function base64ToBuffer(base64) {
    const binaryString = atob(base64);
    const buffer = new Uint8Array(binaryString.length);

    for (let i = 0; i < binaryString.length; i++) {
        buffer[i] = binaryString.charCodeAt(i);
    }

    return buffer.buffer;
}
