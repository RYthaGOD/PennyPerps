/**
 * t_ghost_trade.ts
 * 
 * End-to-end test for Ghost Protocol:
 * 1. Register Ghost Key for a User account.
 * 2. Connect to Dark Matcher.
 * 3. Send signed intent and verify execution.
 */

import "dotenv/config";
import {
    Connection,
    Keypair,
    PublicKey,
    Transaction,
    TransactionInstruction,
    sendAndConfirmTransaction,
    Ed25519Program,
    SYSVAR_INSTRUCTIONS_PUBKEY,
    SYSVAR_CLOCK_PUBKEY,
} from "@solana/web3.js";
import * as fs from "fs";
import nacl from 'tweetnacl';
import bs58 from 'bs58';
import WebSocket from 'ws';

const PROGRAM_ID = new PublicKey("Perco1ator111111111111111111111111111111111");
const MATCHER_URL = "ws://localhost:8080";
const MATCHER_PUBKEY = "3bftR1sLgYHPi45gVywrhw2CDotx7mYBJQvZsbjRfPdE"; // From server logs

async function main() {
    const connection = new Connection("https://api.devnet.solana.com", "confirmed");
    const walletPath = process.env.WALLET_PATH || `${process.env.HOME}/.config/solana/id.json`;
    const payer = Keypair.fromSecretKey(
        new Uint8Array(JSON.parse(fs.readFileSync(walletPath, "utf-8")))
    );

    const market = JSON.parse(fs.readFileSync("meme-market.json", "utf-8"));
    const slab = new PublicKey(market.slab);

    // 1. Generate Ghost Keys
    console.log("Step 1: Generating Ghost Identity...");
    const ghostKeys = nacl.sign.keyPair();
    const ghostPubkey = bs58.encode(ghostKeys.publicKey);
    const encryptionKeys = nacl.box.keyPair();

    // 2. Register Ghost Key on-chain
    console.log("Step 2: Registering Ghost Key on-chain...");
    const userIdx = 0; // Assume first user
    const ixData = Buffer.alloc(1 + 2 + 32);
    ixData.writeUInt8(22, 0); // RegisterGhost
    ixData.writeUInt16LE(userIdx, 1);
    Buffer.from(ghostKeys.publicKey).copy(ixData, 3);

    const regTx = new Transaction().add(
        new TransactionInstruction({
            programId: PROGRAM_ID,
            keys: [
                { pubkey: payer.publicKey, isSigner: true, isWritable: false },
                { pubkey: slab, isSigner: false, isWritable: true },
            ],
            data: ixData
        })
    );
    await sendAndConfirmTransaction(connection, regTx, [payer]);
    console.log("Ghost Identity Registered.");

    // 3. Connect to Dark Matcher
    console.log("Step 3: Connecting to Dark Matcher...");
    const ws = new WebSocket(MATCHER_URL);

    ws.on('open', () => {
        console.log("Connected to Matcher. Sending signed intent...");

        // Auth
        ws.send(JSON.stringify({ type: 'auth', pubKey: ghostPubkey }));

        // Construct Trade Intent
        const side = 'LONG';
        const size = 1000;
        const lpIdx = 1;
        const nonce = 0;

        const msg = Buffer.alloc(28);
        msg.writeUInt16LE(lpIdx, 0);
        msg.writeUInt16LE(userIdx, 2);
        // Size as i128
        const sizeVal = BigInt(size);
        const sizeBuf = Buffer.alloc(16);
        sizeBuf.writeBigInt64LE(sizeVal & 0xFFFFFFFFFFFFFFFFn, 0);
        sizeBuf.writeBigInt64LE(sizeVal >> 64n, 8);
        sizeBuf.copy(msg, 4);
        msg.writeBigUint64LE(BigInt(nonce), 20);

        const signature = nacl.sign.detached(msg, ghostKeys.secretKey);

        const intent = {
            lpIdx,
            userIdx,
            size: sizeVal.toString(),
            nonce: nonce.toString(),
            signature: bs58.encode(signature),
            ghostPubKey: ghostPubkey,
            slab: market.slab,
            oracle: market.oracle || market.slab, // Use slab as placeholder if hyperp
            ticker: "PEPE-PERP",
            side
        };

        // Encrypt for Matcher
        const nonceEnc = nacl.randomBytes(nacl.box.nonceLength);
        const ciphertext = nacl.box(
            Buffer.from(JSON.stringify(intent)),
            nonceEnc,
            bs58.decode(MATCHER_PUBKEY),
            encryptionKeys.secretKey
        );

        ws.send(JSON.stringify({
            type: 'post_intent',
            encrypted: {
                nonce: bs58.encode(nonceEnc),
                ciphertext: bs58.encode(ciphertext),
                senderPubKey: bs58.encode(encryptionKeys.publicKey)
            }
        }));
    });

    ws.on('message', (data) => {
        const msg = JSON.parse(data.toString());
        console.log("Received from Matcher:", msg);
        if (msg.type === 'fill_report' && msg.status === 'confirmed') {
            console.log("SUCCESS: Ghost Trade Executed and Confirmed!");
            ws.close();
            process.exit(0);
        }
    });

    ws.on('error', console.error);
}

main().catch(console.error);
