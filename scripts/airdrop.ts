
import "dotenv/config";
import { Connection, Keypair, LAMPORTS_PER_SOL } from "@solana/web3.js";
import fs from "fs";

// Load config
const RPC_URL = process.env.SOLANA_RPC_URL || "https://api.devnet.solana.com";
const WALLET_PATH = process.env.WALLET_PATH;

if (!WALLET_PATH) {
    console.error("WALLET_PATH not set in .env");
    process.exit(1);
}

try {
    const secretKey = Uint8Array.from(JSON.parse(fs.readFileSync(WALLET_PATH, "utf-8")));
    const keypair = Keypair.fromSecretKey(secretKey);
    const conn = new Connection(RPC_URL, "confirmed");

    console.log(`Requesting airdrop for ${keypair.publicKey.toBase58()}...`);

    // Request 2 SOL
    const sig = await conn.requestAirdrop(keypair.publicKey, 2 * LAMPORTS_PER_SOL);
    console.log(`Airdrop requested. Signature: ${sig}`);

    await conn.confirmTransaction(sig);
    console.log("✅ Airdrop confirmed!");

    const balance = await conn.getBalance(keypair.publicKey);
    console.log(`New Balance: ${balance / LAMPORTS_PER_SOL} SOL`);

} catch (e) {
    console.error("Airdrop failed:", e);
    process.exit(1);
}
