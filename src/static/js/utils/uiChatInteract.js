import {encryptMessage, hashData, generateKyberKeyPair, decryptMessage, deriveKey} from './encryption.js';
import {convertToHex, hexToUint8Array} from './convertions.js';
import {decryptSharedSecrets, setup, clearChat} from './utils.js'
import {sendKyberKey, emitMessage, establishTCPConnection} from './tcp.js';
import {setupChatDatabase, displayAllChats, setupMessageDatabase, checkOutdatedMessages, saveChat, loadMessages, saveMessage} from './database.js'
const bcrypt = require('bcrypt');

export async function addChat() {
    const name = document.getElementById("chat_name").value;
    const destId = document.getElementById("user_id").value;
    const newButton = document.createElement('button');
    const chat_data = { name: name, user_id: destId, timestamp: Date.now() }
    allDestIds.push(destId);
    newButton.classList.add('sidebar-button');
    const chatNum = await saveChat(chat_data);   
    newButton.textContent = name;
    newButton.dataset.destId = destId;
    newButton.dataset.chatid = chatNum;
    newButton.addEventListener('click', async () => {
        currentChatDestUserId = destId;
        currentChatNum = chatNum;
        if (!sharedSecret[destId]) {
            let publicKey, privateKey;
            [publicKey, privateKey] = await kyberInstance.generateKeyPair();
            PrivateKeyList[destId] = privateKey;
            sendKyberKey(kyberPublicKey);
        }
        clearChat();
        openChatContainer();
        loadMessages(chatNum);
    }); 
    const sidebar = document.querySelector('.sidebar');
    if (!areChatsDisplayed) {
        newButton.style.display = 'none';
    }
    sidebar.appendChild(newButton);
    document.getElementById("chat_name").value = '';
    document.getElementById("user_id").value = '';
    document.querySelectorAll('.invite-button').forEach((element) => {
        let userId = element.dataset.userId;
        if (allDestIds.includes(userId)) {
            element.remove();
            let invites = JSON.parse(localStorage.getItem('invites')) || {};
            delete invites[userId];
            localStorage.setItem('invites', JSON.stringify(invites));
        }
    });
    closeModal();
}
export function toggleSidebar() {
    const sidebar = document.getElementById("sidebar");
    const toggleButton = document.querySelector(".toggle-sidebar-btn");
    const chatContainer = document.getElementById("chatContainer");

    sidebar.classList.toggle("visible");

    if (sidebar.classList.contains("visible")) {
        sidebar.style.width = "300px";
        toggleButton.style.left = "300px";

        chatContainer.classList.add("sidebar-visible");
    } else {
        sidebar.style.width = "0";
        toggleButton.style.left = "10px";
        chatContainer.classList.remove("sidebar-visible");
    }
}

export async function sendMessage() {
    const fileInput = document.getElementById('fileInput');
    const textarea = document.querySelector('.input-textarea');
    const thing = textarea.value;
    addMessageToHistory(`${thing}`, 'client', currentChatNum);
    const message = thing.replace(/ /g, '&nbsp;').replace(/\n/g, '<br>');
    if (!message && !fileInput) {
        alert("Please enter a message or select a file.");
        return;
    }
    const encoder = new TextEncoder();
    const bytes = encoder.encode(message);
    const encryptedMessage = await encryptMessage(bytes, sharedSecret[currentChatDestUserId]);
    emitMessage(encryptedMessage);
    textarea.value = null;
}
export function addMessageToHistory(message, type, chatId, sourceId) {
    if (sourceId == currentChatDestUserId || type == "client") {
        const messagesContainer = document.querySelector('.messages');
        const newMessage = document.createElement('div');
        newMessage.textContent = message.replace(/&nbsp;/g, ' ').replace(/<br>/g, '\n');
        newMessage.classList.add('message', type);
        messagesContainer.appendChild(newMessage);
    
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }
    const messageData = {
        chatid: chatId,
        message: message,
        type: type,
        timestamp: new Date().toISOString(),
    };

    saveMessage(messageData).catch((error) => {
        console.error("Error saving message to database:", error);
    });
    const messageInput = document.querySelector('.input-textarea'); 
    messageInput.value = '';
}
function closeChatContainer() {
    const chatContainer = document.getElementById('chatContainer');
    if (chatContainer) {
        document.body.removeChild(chatContainer);
        isChatShowed = false;
    }
}
function loadBackground() {
    const savedBackground = localStorage.getItem('chatBackground');
    
    if (savedBackground) {
      const mainContent = document.getElementById('chatContainer');
      
      if (savedBackground.startsWith('data:image')) {
        mainContent.style.backgroundImage = `url(${savedBackground})`;
        mainContent.style.backgroundColor = '';
      } else if (savedBackground.startsWith('#')) {
        mainContent.style.backgroundColor = savedBackground;
        mainContent.style.backgroundImage = '';
      } else {
        mainContent.style.backgroundImage = `url(${savedBackground})`;
        mainContent.style.backgroundColor = '';
      }
    }
}
export function openChatContainer() {
    const chatContainer = document.getElementById('chatContainer');
    loadBackground()
    chatContainer.style.display = 'flex';
}
export function openModal() {
    const modal = document.getElementById("chatModal");
    modal.style.display = "flex";
}
export function closeModal() {
    const modal = document.getElementById("chatModal");
    modal.style.display = "none";
}
export async function initializeKyber() {
    try {
        const { Kyber1024 } = await import("https://esm.sh/crystals-kyber-js@1.1.1");
        window.kyberInstance = new Kyber1024();
    } catch (error) {
        console.error("Error loading Kyber1024:", error);
    }
};
async function loadDilithiumKeys() {
    const encryptedPvKeyHex = localStorage.getItem('privateKey');
    const encryptedPbKeyHex = localStorage.getItem('publicKey');
    if (!encryptedPvKeyHex | !encryptedPbKeyHex) {
        return;
    }
    const mnemonicKeyHex = localStorage.getItem('mnemonicKey');
    const mnemonicKey = hexToUint8Array(mnemonicKeyHex);

    const dataBuffer = mnemonicKey;
    const salt = dataBuffer.slice(0, 16);
    const nonce = dataBuffer.slice(16, 28);
    const encryptedData = dataBuffer.slice(28);
    const aesKey = await deriveKey(password, salt);
    const decryptedData = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce },
        aesKey,
        encryptedData
    );
    const pvKey = await decryptMessage(hexToUint8Array(encryptedPvKeyHex), decryptedData, "message");
    const pbKey = await decryptMessage(hexToUint8Array(encryptedPbKeyHex), decryptedData, "message");
    dilithiumKeyPair = dilithium.Keys.restore(new Uint8Array(pbKey),new Uint8Array(pvKey));
    return 1;
}
export async function submitPassword() {
    if (!pageLoaded) {
        alert('The page is not fully loaded yet please wait a bit');
    }
    password = document.getElementById('passwordInput').value;
    if (!password | !await checkPassword(password) ) {
        return;
    }
    await decryptSharedSecrets();
    try {
        if (mnemonicKey) {
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const nonce = crypto.getRandomValues(new Uint8Array(12));
            const aesKey = await deriveKey(password, salt);
            const encryptedData = await window.crypto.subtle.encrypt(
                { name: "AES-GCM", iv: nonce },
                aesKey,
                mnemonicKey
            );
            const combinedData = new Uint8Array(salt.byteLength + nonce.byteLength + encryptedData.byteLength);
            combinedData.set(new Uint8Array(salt.buffer), 0);
            combinedData.set(new Uint8Array(nonce.buffer), salt.byteLength);
            combinedData.set(new Uint8Array(encryptedData), salt.byteLength + nonce.byteLength);
            localStorage.setItem('mnemonicKey', convertToHex(combinedData));
        }
        await loadDilithiumKeys();
        await establishTCPConnection();
        await initializeKyber();
        await setupChatDatabase();
        await generateKyberKeyPair();
        displayAllChats();
        await setupMessageDatabase();
        await setup();
        
        setInterval(checkOutdatedMessages, 5000);
        document.getElementById('passwordPopup').style.display = 'none';
    } catch (error) {
        console.error("Error during initialization:", error);
    }
}
export async function checkPassword(password) {
    const storedHashedPassword = localStorage.getItem('hashedPassword');

    if (!storedHashedPassword) {
        // First-time password setup
        const hashedPassword = await bcrypt.hash(password, 20);
        localStorage.setItem('hashedPassword', hashedPassword);
        alert("Password successfully set");
        return true;
    } else {
        // Compare entered password with stored hash
        const match = await bcrypt.compare(password, storedHashedPassword);
        if (match) {
            console.log('Password is correct!');
            return true;
        } else {
            alert("Incorrect password. Please try again.");
            return false;
        }
    }
}
export function openWebpage() {
    window.open(`/register`, '_blank');
}
