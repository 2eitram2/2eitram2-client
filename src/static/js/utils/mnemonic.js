const bip39 = require("bip39");
const crypto = require("crypto");
import {generateDilithiumKeys} from './signing.js';

export function loadMnemonic() {
    mnemonic = bip39.generateMnemonic(256);
    const words = mnemonic.split(" ");
    const container = document.getElementById("mnemonic-container");

    const title = document.createElement("h2");
    title.classList.add("mnemonic-title");
    title.textContent = "Your Mnemonic Words";
    container.appendChild(title);

    const wordsContainer = document.createElement("div");
    wordsContainer.classList.add("words-container");

    words.forEach(word => {
        const wordElement = document.createElement("span");
        wordElement.classList.add("word");
        wordElement.textContent = word;
        wordsContainer.appendChild(wordElement);
    });
    
    container.appendChild(wordsContainer);

    const closeButton = document.createElement("button");
    closeButton.classList.add("close-btn");
    closeButton.textContent = "Once clicked those words are gone forever";
    container.appendChild(closeButton);


    closeButton.addEventListener("click", () => {
        container.style.display = "none";
        document.getElementById('passwordPopup').style.display = 'flex';
    });
}

export function copyMnemonic() {
    navigator.clipboard.writeText(mnemonic).then(() => {
        alert("Mnemonic copied to clipboard!");
    });
}
export function handleSetup() {
    mnemonicKey = crypto.pbkdf2Sync(mnemonic, "salt", 100000, 32, "sha256");
    generateDilithiumKeys().then(result => {
        console.log(result);
    }).catch(error => {
        console.error(error);
    });
    

}