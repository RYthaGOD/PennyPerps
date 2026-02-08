// Basic verification script for Ghost SDK
import { GhostKeyRing } from "../src/lib/ghost-sdk";
import nacl from 'tweetnacl';
import bs58 from 'bs58';

// Polyfill LocalStorage for Node env
const localStorageMock = (() => {
    let store: Record<string, string> = {};
    return {
        getItem: (key: string) => store[key] || null,
        setItem: (key: string, value: string) => store[key] = value,
        removeItem: (key: string) => delete store[key],
        clear: () => store = {}
    };
})();
if (typeof global !== 'undefined') {
    (global as any).localStorage = localStorageMock;
    (global as any).window = {};
}

console.log("Testing Ghost Key Ring...");

// 1. Init
const alice = new GhostKeyRing();
console.log("Alice PubKey (Ed25519):", alice.pubKey);
console.log("Alice EncKey (X25519):", alice.encryptPubKey);

// 2. Mock Matcher
const matcher = nacl.box.keyPair();
const matcherPub58 = bs58.encode(matcher.publicKey);
console.log("Matcher PubKey:", matcherPub58);

// 3. Encrypt Message for Matcher
const msg = new TextEncoder().encode("BUY PEPE 100x");
const encrypted = alice.encryptFor(matcherPub58, msg);
console.log("Encrypted:", encrypted);

// 4. Decrypt as Matcher
const opened = nacl.box.open(
    bs58.decode(encrypted.ciphertext),
    bs58.decode(encrypted.nonce),
    bs58.decode(alice.encryptPubKey),
    matcher.secretKey
);

if (opened) {
    const text = new TextDecoder().decode(opened);
    console.log("Decrypted Message:", text);
    if (text === "BUY PEPE 100x") {
        console.log("✅ Encryption/Decryption SUCCESS");
    } else {
        console.log("❌ Content Mismatch");
    }
} else {
    console.log("❌ Decryption Failed");
}

// 5. Test Persistence
const savedKey = localStorage.getItem('GHOST_SIGNING_KEY');
console.log("Saved Key in Storage:", !!savedKey);

const aliceReborn = new GhostKeyRing();
if (aliceReborn.pubKey === alice.pubKey) {
    console.log("✅ Persistence SUCCESS");
} else {
    console.log("❌ Persistence Failed");
}
