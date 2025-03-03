import {convertToHex, } from './convertions.js';
import {encryptMessage} from './encryption.js';

export async function generateDilithiumKeys() {
    dilithiumKeyPair = new dilithium.Keys();
    dilithiumKeyPair = dilithium.Keys.restore(dilithiumKeyPair.pubkey, dilithiumKeyPair.secret);
    await saveDilithiumKeys();
}

async function saveDilithiumKeys() {
    const encryptedPvKey = await encryptMessage(dilithiumKeyPair.secret, mnemonicKey);
    const encryptedPbKey = await encryptMessage(dilithiumKeyPair.pubkey, mnemonicKey);
    localStorage.setItem('privateKey', convertToHex(encryptedPvKey));
    localStorage.setItem('publicKey', convertToHex(encryptedPbKey));
}
