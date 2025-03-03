import {submitPassword, toggleSidebar, openModal, closeModal, addChat, sendMessage} from './utils/uiChatInteract.js';
import {removeChat, loadInvites} from './utils/utils.js'
import { Kyber1024 } from './cdn/kyber.js';
import {copyMnemonic, loadMnemonic, handleSetup} from './utils/mnemonic.js'
import './utils/tcp.js'

window.currentChatDestUserId = null;
window.currentChatNum = null;
window.isChatShowed = false;
window.chatDb = null;
window.messageDb = null;
window.areChatsDisplayed = 1;
window.kyberInstance = new Kyber1024();
window.kyberPublicKey = null;
window.kyberPrivateKey = null;
window.allDestIds = [];
window.onlineIds = [];
window.PrivateKeyList = {};
window.sharedSecret = {};
window.password = null;
window.pageLoaded = false;
window.encryptionExternalKey = {};
window.dilithiumKeyPair = null;
window.dilithium = require('pqc_dilithium');
window.client = null;
window.mnemonic = null;
window.mnemonicKey = null;
window.PORT = 8081;
//window.HOST = '148.113.191.144';
window.HOST = '192.168.0.70';

window.onload = function() {
    window.pageLoaded = true;

    const loadingScreen = document.getElementById('loading-screen');
    const mainContent = document.getElementById('main');
    loadingScreen.style.display = 'none';
    mainContent.style.visibility = 'visible';

    const copyMnemonicButton = document.getElementById('copy-mnemonic');
    copyMnemonicButton.addEventListener('click', copyMnemonic);

    const submitButton = document.getElementById('submitButton');
    submitButton.addEventListener('click', submitPassword);

    const sidebarButton = document.getElementById('sidebarButton');
    sidebarButton.addEventListener('click', toggleSidebar);

    const addChatButton = document.getElementById('addChatButton');
    addChatButton.addEventListener('click', openModal);

    const addChatModalCancelButton = document.getElementById('addChatModalCancelButton');
    addChatModalCancelButton.addEventListener('click', closeModal)

    const addChatModalSubmmitButton = document.getElementById('addChatModalSubmmitButton');
    addChatModalSubmmitButton.addEventListener('click', addChat)
    
    const removeChatButton = document.getElementById('removeChatButton');
    removeChatButton.addEventListener('click', removeChat)

    const sendMessageButton = document.getElementById('sendMessageButton');
    sendMessageButton.addEventListener('click', sendMessage);

    const chatInvitesButton = document.getElementById('chatInvitesButton');
    chatInvitesButton.addEventListener('click', loadInvites)

    const privateKey = localStorage.getItem('privateKey');
    if (!privateKey) {
        document.getElementById('mnemonic-container').style.display = 'flex';
        loadMnemonic();
        handleSetup();
    } else {
        document.getElementById('passwordPopup').style.display = 'flex';
    }
}
