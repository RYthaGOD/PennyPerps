import nacl from 'tweetnacl';
import bs58 from 'bs58';

/*
 * GhostKeyRing: Manages ephemeral keys for the Dark Pool simulation.
 * 
 * Keys:
 * - Signing Key (Ed25519): Used to sign Intents (Orders). This is your "Wallet" identity.
 * - Encryption Key (Curve25519/X25519): Used to encrypt/decrypt messages with the Matcher.
 */

export interface Helper {
    encodeUTF8: (s: string) => Uint8Array;
    decodeUTF8: (s: Uint8Array) => string;
}

// Minimal polyfill for encoding if not available
const encodeUTF8 = (s: string) => new TextEncoder().encode(s);
const decodeUTF8 = (s: Uint8Array) => new TextDecoder().decode(s);

export class GhostKeyRing {
    private signingKeyPair: nacl.SignKeyPair;
    private encryptionKeyPair: nacl.BoxKeyPair;

    constructor() {
        // In a real app, we'd load from localStorage here.
        // For simulation, we generate fresh keys or load if exists.
        this.signingKeyPair = nacl.sign.keyPair();
        this.encryptionKeyPair = nacl.box.keyPair();

        // Try to load from storage if running in browser
        if (typeof window !== 'undefined') {
            const storedSk = localStorage.getItem('GHOST_SIGNING_KEY');
            if (storedSk) {
                const sk = bs58.decode(storedSk);
                this.signingKeyPair = nacl.sign.keyPair.fromSecretKey(sk);
            } else {
                this.save();
            }

            const storedEncSk = localStorage.getItem('GHOST_ENCRYPTION_KEY');
            if (storedEncSk) {
                const sk = bs58.decode(storedEncSk);
                this.encryptionKeyPair = nacl.box.keyPair.fromSecretKey(sk);
            } else {
                this.save();
            }
        }
    }

    private save() {
        if (typeof window === 'undefined') return;
        localStorage.setItem('GHOST_SIGNING_KEY', bs58.encode(this.signingKeyPair.secretKey));
        localStorage.setItem('GHOST_ENCRYPTION_KEY', bs58.encode(this.encryptionKeyPair.secretKey));
    }

    // Public Accessors
    get pubKey(): string {
        return bs58.encode(this.signingKeyPair.publicKey);
    }

    get encryptPubKey(): string {
        return bs58.encode(this.encryptionKeyPair.publicKey);
    }

    // Operations
    sign(message: Uint8Array): Uint8Array {
        return nacl.sign.detached(message, this.signingKeyPair.secretKey);
    }

    // Box Encryption: Encrypt a message for a Receiver (Matcher)
    encryptFor(receiverPubkey58: string, message: Uint8Array): { nonce: string, ciphertext: string } {
        const receiverPk = bs58.decode(receiverPubkey58);
        const nonce = nacl.randomBytes(nacl.box.nonceLength);
        const ciphertext = nacl.box(
            message,
            nonce,
            receiverPk,
            this.encryptionKeyPair.secretKey
        );
        return {
            nonce: bs58.encode(nonce),
            ciphertext: bs58.encode(ciphertext)
        };
    }

    // Box Decryption: Decrypt a message from a Sender (Matcher)
    decryptFrom(senderPubkey58: string, nonce58: string, ciphertext58: string): Uint8Array | null {
        const senderPk = bs58.decode(senderPubkey58);
        const nonce = bs58.decode(nonce58);
        const ciphertext = bs58.decode(ciphertext58);

        return nacl.box.open(
            ciphertext,
            nonce,
            senderPk,
            this.encryptionKeyPair.secretKey
        );
    }

    // Reset (Destroy Keys)
    burn() {
        if (typeof window !== 'undefined') {
            localStorage.removeItem('GHOST_SIGNING_KEY');
            localStorage.removeItem('GHOST_ENCRYPTION_KEY');
        }
        this.signingKeyPair = nacl.sign.keyPair();
        this.encryptionKeyPair = nacl.box.keyPair();
    }
}
