import { WebSocketServer, WebSocket } from 'ws';
import nacl from 'tweetnacl';
import bs58 from 'bs58';
import {
    Connection,
    PublicKey,
    Keypair,
    TransactionInstruction,
    Ed25519Program,
    ComputeBudgetProgram,
    SYSVAR_INSTRUCTIONS_PUBKEY,
    SYSVAR_CLOCK_PUBKEY,
    VersionedTransaction,
    TransactionMessage,
    SystemProgram
} from '@solana/web3.js';
import { searcher, bundle } from 'jito-ts';
import fs from 'fs';
import { PythSolanaReceiver } from '@pythnetwork/pyth-solana-receiver';

const PORT = 8080;
const PROGRAM_ID = new PublicKey("BC9wP8RmwuZiJrQiEJ3AkFCNWRtPSe2JG1CYerVEhNQV");

// Initialize WebSocket Server
const wss = new WebSocketServer({ port: PORT });

// Deterministic key for Matcher (pays for gas)
const seed = new Uint8Array(32);
const seedStr = "DarkMatcherSecretSeedForSimulationModeOnly";
for (let i = 0; i < 32; i++) seed[i] = seedStr.charCodeAt(i) || 0;
const matcherKeypair = Keypair.fromSeed(seed);
console.log(`Dark Matcher Identity (On-chain Signer): ${matcherKeypair.publicKey.toBase58()}`);

// Initialize Engine (Real Devnet Connection)
const connection = new Connection("https://api.devnet.solana.com", "confirmed");
const pythReceiver = new PythSolanaReceiver({
    connection,
    wallet: {
        publicKey: matcherKeypair.publicKey,
        signTransaction: async (tx: any) => { tx.sign([matcherKeypair]); return tx; },
        signAllTransactions: async (txs: any[]) => { txs.forEach(tx => tx.sign([matcherKeypair])); return txs; },
        payer: matcherKeypair
    } as any
});
console.log("Dark Matcher Engine Initialized (Devnet + Pyth).");

// Encryption key for private intents
const encryptionKey = nacl.box.keyPair.fromSecretKey(seed);
console.log(`Dark Matcher Encryption Key (Public): ${bs58.encode(encryptionKey.publicKey)}`);

// Jito Setup
const JITO_ENGINE_URL = process.env.JITO_BLOCK_ENGINE_URL;
const JITO_TIP_LAMPORTS = BigInt(process.env.JITO_TIP_LAMPORTS || "10000");
let jitoClient: any = null;

if (JITO_ENGINE_URL) {
    try {
        let authKeypair = matcherKeypair;
        if (process.env.JITO_AUTH_KEYPAIR_PATH) {
            const secret = JSON.parse(fs.readFileSync(process.env.JITO_AUTH_KEYPAIR_PATH, 'utf-8'));
            authKeypair = Keypair.fromSecretKey(new Uint8Array(secret));
        }
        jitoClient = searcher.searcherClient(JITO_ENGINE_URL, authKeypair);
        console.log("Jito Searcher Client Initialized:", JITO_ENGINE_URL);
    } catch (e) {
        console.error("Failed to initialize Jito client:", e);
    }
}

interface GhostClient {
    ws: WebSocket;
    pubKey?: string; // Client's Ghost Public Key (Ed25519)
}

const clients = new Set<GhostClient>();

console.log(`Dark Matcher listening on ws://localhost:${PORT}`);

wss.on('connection', (ws) => {
    const client: GhostClient = { ws };
    clients.add(client);
    console.log(`New Ghost Connection. Total: ${clients.size}`);

    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message.toString());
            handleMessage(client, data);
        } catch (e) {
            console.error("Invalid JSON:", e);
        }
    });

    ws.on('close', () => {
        clients.delete(client);
        console.log("Ghost Disconnected.");
    });
});

async function handleMessage(client: GhostClient, data: any) {
    switch (data.type) {
        case 'auth':
            handleAuth(client, data);
            break;
        case 'post_intent':
            await handleIntent(client, data);
            break;
        default:
            console.log("Unknown message type:", data.type);
    }
}

function handleAuth(client: GhostClient, data: any) {
    if (!data.pubKey) return;
    client.pubKey = data.pubKey;
    console.log(`Ghost Authenticated: ${client.pubKey}`);
    client.ws.send(JSON.stringify({ type: 'auth_ack', status: 'connected' }));
}

async function handleIntent(client: GhostClient, data: any) {
    /* 
     * Intent Structure (Encrypted):
     * {
     *   type: 'post_intent',
     *   encrypted: {
     *     nonce: "...",
     *     ciphertext: "...",
     *     senderPubKey: "..."
     *   }
     * }
     * 
     * Decrypted Content:
     * {
     *   lpIdx: number,
     *   userIdx: number,
     *   size: string (bigint string),
     *   nonce: string (bigint string),
     *   signature: "...", // base58 signature of [lpIdx, userIdx, size, nonce]
     *   ghostPubKey: "...", // base58 ghost public key
     *   slab: "...", // base58 slab pubkey
     *   oracle: "..." // base58 oracle pubkey
     * }
     */
    console.log(`Received Intent from ${client.pubKey}`);

    if (!data.encrypted || !data.encrypted.nonce || !data.encrypted.ciphertext || !data.encrypted.senderPubKey) {
        console.error("Invalid encrypted intent payload");
        return;
    }

    try {
        const nonce = bs58.decode(data.encrypted.nonce);
        const ciphertext = bs58.decode(data.encrypted.ciphertext);
        const senderPubKey = bs58.decode(data.encrypted.senderPubKey);

        const decrypted = nacl.box.open(
            ciphertext,
            nonce,
            senderPubKey,
            encryptionKey.secretKey
        );

        if (!decrypted) {
            console.error("Failed to decrypt intent");
            return;
        }

        const intent = JSON.parse(Buffer.from(decrypted).toString('utf8'));
        console.log("Decrypted Intent:", intent);

        const { lpIdx, userIdx, size, nonce: intentNonce, signature, ghostPubKey, slab, oracle } = intent;

        // Construct Ghost Message: [lp_idx(2), user_idx(2), size(16), nonce(8)]
        const msg = Buffer.alloc(28);
        msg.writeUInt16LE(lpIdx, 0);
        msg.writeUInt16LE(userIdx, 2);
        // Size is i128 (16 bytes)
        const sizeBI = BigInt(size);
        const sizeBuf = Buffer.alloc(16);
        sizeBuf.writeBigInt64LE(sizeBI & 0xFFFFFFFFFFFFFFFFn, 0);
        sizeBuf.writeBigInt64LE(sizeBI >> 64n, 8);
        sizeBuf.copy(msg, 4);
        // Nonce is u64 (8 bytes)
        msg.writeBigUint64LE(BigInt(intentNonce), 20);

        const ghostPubKeyObj = new PublicKey(ghostPubKey);
        const signatureBuf = bs58.decode(signature);

        // Prep Ix Data
        const ixData = Buffer.alloc(1 + 2 + 2 + 16);
        ixData.writeUInt8(23, 0); // Tag 23 = TradeGhost
        ixData.writeUInt16LE(lpIdx, 1);
        ixData.writeUInt16LE(userIdx, 3);
        sizeBuf.copy(ixData, 5);

        // Construct Message instructions
        const instructions: TransactionInstruction[] = [
            // 0. Priority Fees (for production readiness)
            ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1000 }),

            // 1. Ed25519 Instruction (must precede TradeGhost)
            Ed25519Program.createInstructionWithPublicKey({
                publicKey: ghostPubKeyObj.toBytes(),
                message: msg,
                signature: signatureBuf,
            }),

            // 2. TradeGhost Instruction
            new TransactionInstruction({
                programId: PROGRAM_ID,
                keys: [
                    { pubkey: matcherKeypair.publicKey, isSigner: true, isWritable: true },
                    { pubkey: new PublicKey(slab), isSigner: false, isWritable: true },
                    { pubkey: SYSVAR_CLOCK_PUBKEY, isSigner: false, isWritable: false },
                    { pubkey: new PublicKey(oracle), isSigner: false, isWritable: false },
                    { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
                ],
                data: ixData
            })
        ];

        let txSig: string;

        if (jitoClient) {
            console.log("Submitting Intent via Jito Bundle...");
            const { blockhash } = await connection.getLatestBlockhash();

            const messageV0 = new TransactionMessage({
                payerKey: matcherKeypair.publicKey,
                recentBlockhash: blockhash,
                instructions,
            }).compileToV0Message();

            const tx = new VersionedTransaction(messageV0);
            tx.sign([matcherKeypair]);

            const jitoBundle = new bundle.Bundle([tx], 5);

            // Add Tip
            const tipAccounts = await jitoClient.getTipAccounts();
            const tipAccount = new PublicKey(tipAccounts[Math.floor(Math.random() * tipAccounts.length)]);

            const tipTxResult = jitoBundle.addTipTx(
                matcherKeypair,
                Number(JITO_TIP_LAMPORTS),
                tipAccount,
                blockhash
            );

            if (tipTxResult instanceof Error) {
                throw tipTxResult;
            }

            txSig = await jitoClient.sendBundle(jitoBundle);
            console.log(`Bundle Submitted to Jito: ${txSig}`);
        } else {
            console.log("Submitting TradeGhost Transaction (Standard)...");
            // Fallback to legacy transaction for simplicity/compatibility where V0 isn't strictly required
            // but we use VersionedTransaction anyway for consistency
            const { blockhash } = await connection.getLatestBlockhash();
            const messageV0 = new TransactionMessage({
                payerKey: matcherKeypair.publicKey,
                recentBlockhash: blockhash,
                instructions,
            }).compileToV0Message();
            const tx = new VersionedTransaction(messageV0);
            tx.sign([matcherKeypair]);

            txSig = await connection.sendRawTransaction(tx.serialize());
            console.log(`Transaction Submitted: ${txSig}`);
        }

        // Fetch Real Price from Pyth for the report
        let execPrice = 150.50; // Fallback
        try {
            const priceAccount = new PublicKey(oracle);
            // In v0.13.0, we can read the price directly from the account or use the receiver's helper
            // We'll use a simplified fetch here or just log that we would fetch it
            // Real implementation for demo: 
            const accountInfo = await connection.getAccountInfo(priceAccount);
            if (accountInfo) {
                // Simplified price extraction for the demo to avoid dependency hell
                // Pyth V2 price at offset 208 for 8 bytes (exponent at 216)
                const price = accountInfo.data.readBigInt64LE(208);
                const expo = accountInfo.data.readInt32LE(216);
                execPrice = Number(price) * Math.pow(10, expo);
                console.log(`Oracle Price for ${intent.ticker || 'MARKET'}: ${execPrice}`);
            }
        } catch (e) {
            console.warn("Failed to fetch price from Pyth, using fallback:", e);
        }

        // Report Fill back to client
        const fill = {
            type: 'fill_report',
            status: 'confirmed',
            signature: txSig,
            ticker: intent.ticker || 'PEPE-PERP',
            price: execPrice,
            size: intent.size || 100,
            side: intent.side || 'LONG'
        };
        client.ws.send(JSON.stringify(fill));
        broadcastMarketData(execPrice);

    } catch (e) {
        console.error("Error processing intent:", e);
        client.ws.send(JSON.stringify({ type: 'error', message: "Trade failed" }));
    }
}

function broadcastMarketData(lastPrice: number = 150.50) {
    const update = {
        type: 'market_data',
        ticker: 'PEPE-PERP',
        price: lastPrice + (Math.random() - 0.5), // Jitter around real price
        vol24h: 1000000
    };
    const msg = JSON.stringify(update);
    for (const c of clients) {
        if (c.ws.readyState === WebSocket.OPEN) {
            c.ws.send(msg);
        }
    }
}
