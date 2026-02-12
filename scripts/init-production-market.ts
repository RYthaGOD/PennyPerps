import "dotenv/config";
import {
    Connection,
    Keypair,
    PublicKey,
    Transaction,
    sendAndConfirmTransaction,
    ComputeBudgetProgram,
    SystemProgram,
    SYSVAR_CLOCK_PUBKEY,
    LAMPORTS_PER_SOL,
} from "@solana/web3.js";
import {
    getOrCreateAssociatedTokenAccount,
    TOKEN_PROGRAM_ID,
    NATIVE_MINT,
} from "@solana/spl-token";
import * as fs from "fs";

// NEW PROGRAM ID from deployment
const PROGRAM_ID = new PublicKey("6u8921CKtcMbrR8sfHdc9M6V2NnymqCoKMLURtmivvxE");

// Chainlink SOL/USD on devnet
const CHAINLINK_SOL_USD = new PublicKey("99B2bTijsU6f1GCT73HmdR7HCFFjGMBcPZY6jZ96ynrR");

// Slab size for production.so
const SLAB_SIZE = 992560;

async function main() {
    console.log("\\n" + "=".repeat(70));
    console.log("PENNY PERPS: DEVNET MARKET INITIALIZATION");
    console.log("=".repeat(70));
    console.log(`\\nProgram ID: ${PROGRAM_ID.toBase58()}`);

    // Setup connection and wallet
    const walletPath = process.env.WALLET_PATH || `${process.env.HOME}/.config/solana/id.json`;
    const payer = Keypair.fromSecretKey(
        new Uint8Array(JSON.parse(fs.readFileSync(walletPath, "utf-8")))
    );
    const connection = new Connection("https://api.devnet.solana.com", "confirmed");

    console.log(`Wallet: ${payer.publicKey.toBase58()}`);
    const balance = await connection.getBalance(payer.publicKey);
    console.log(`Balance: ${(balance / LAMPORTS_PER_SOL).toFixed(4)} SOL\\n`);

    // Create slab account
    console.log("Step 1: Creating slab account...");
    const slab = Keypair.generate();
    console.log(`  Slab: ${slab.publicKey.toBase58()}`);

    const rentExempt = await connection.getMinimumBalanceForRentExemption(SLAB_SIZE);
    console.log(`  Rent: ${(rentExempt / LAMPORTS_PER_SOL).toFixed(4)} SOL`);

    const createSlabTx = new Transaction();
    createSlabTx.add(ComputeBudgetProgram.setComputeUnitLimit({ units: 100000 }));
    createSlabTx.add(SystemProgram.createAccount({
        fromPubkey: payer.publicKey,
        newAccountPubkey: slab.publicKey,
        lamports: rentExempt,
        space: SLAB_SIZE,
        programId: PROGRAM_ID,
    }));

    const sig = await sendAndConfirmTransaction(connection, createSlabTx, [payer, slab], { commitment: "confirmed" });
    console.log(`  Created slab: ${sig}`);

    // Create InitMarket instruction manually
    console.log("\\nStep 2: Initializing market...");

    // Build InitMarket instruction data (tag 0)
    const initData = Buffer.alloc(1);
    initData.writeUInt8(0, 0); // InitMarket tag

    const initTx = new Transaction();
    initTx.add(ComputeBudgetProgram.setComputeUnitLimit({ units: 200000 }));
    initTx.add({
        programId: PROGRAM_ID,
        keys: [
            { pubkey: payer.publicKey, isSigner: true, isWritable: true },
            { pubkey: slab.publicKey, isSigner: false, isWritable: true },
        ],
        data: initData,
    });

    const initSig = await sendAndConfirmTransaction(connection, initTx, [payer], {
        commitment: "confirmed",
        skipPreflight: true
    });
    console.log(`  Market initialized: ${initSig}`);

    // Save market info
    const marketInfo = {
        network: "devnet",
        createdAt: new Date().toISOString(),
        programId: PROGRAM_ID.toBase58(),
        slab: slab.publicKey.toBase58(),
        mint: NATIVE_MINT.toBase58(),
        oracle: CHAINLINK_SOL_USD.toBase58(),
        admin: payer.publicKey.toBase58(),
    };

    fs.writeFileSync("production-market.json", JSON.stringify(marketInfo, null, 2));
    console.log("\\nMarket info saved to production-market.json");
    console.log("\\n" + "=".repeat(70));
    console.log("MARKET INITIALIZATION COMPLETE!");
    console.log("=".repeat(70) + "\\n");
}

main().catch(console.error);
