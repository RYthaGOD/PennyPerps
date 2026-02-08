import { WebSocketServer, WebSocket } from 'ws';
import nacl from 'tweetnacl';
import bs58 from 'bs58';
import { MockPercolator } from '../mock/MockV3';

const PORT = 8080;

// Initialize Engine
const mock = new MockPercolator("http://localhost:8899");
console.log("Dark Matcher Engine Initialized.");

// Initialize WebSocket Server
const wss = new WebSocketServer({ port: PORT });

// AUDIT FIX: Use deterministic key for Matcher
// Seed: "DarkMatcherSecretSeedForSimulationModeOnly"
const seed = new Uint8Array(32);
const seedStr = "DarkMatcherSecretSeedForSimulationModeOnly";
for (let i = 0; i < 32; i++) seed[i] = seedStr.charCodeAt(i) || 0;

const matcherKey = nacl.box.keyPair.fromSecretKey(seed);
console.log(`Dark Matcher Identity (Public Key): ${bs58.encode(matcherKey.publicKey)}`);
console.log(`(Ensure this matches CONFIG.MATCHER_PUBKEY in client)`);

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

function handleMessage(client: GhostClient, data: any) {
    switch (data.type) {
        case 'auth':
            handleAuth(client, data);
            break;
        case 'post_intent':
            handleIntent(client, data);
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

function handleIntent(client: GhostClient, data: any) {
    /* 
     * Intent Structure:
     * {
     *   type: 'post_intent',
     *   encrypted: {
     *     nonce: "...",
     *     ciphertext: "..."
     *   }
     * }
     */
    console.log(`Received Intent from ${client.pubKey}`);

    // In a real implementation:
    // 1. Decrypt using Server's Secret Key (Not implemented in this mock phase)
    // 2. Mock execution for simulation

    // Simulate Processing Delay
    setTimeout(() => {
        const fill = {
            type: 'fill_report',
            ticker: 'PEPE-PERP',
            price: 150.50, // Mock Price
            size: 100,
            side: 'LONG',
            pnl: 0
        };
        client.ws.send(JSON.stringify(fill));
        broadcastMarketData();
    }, 1000);
}

function broadcastMarketData() {
    const update = {
        type: 'market_data',
        ticker: 'PEPE-PERP',
        price: 150.50 + (Math.random() - 0.5), // Jitter
        vol24h: 1000000
    };
    const msg = JSON.stringify(update);
    for (const c of clients) {
        if (c.ws.readyState === WebSocket.OPEN) {
            c.ws.send(msg);
        }
    }
}
