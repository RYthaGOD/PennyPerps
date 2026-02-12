import "dotenv/config";
import {
    Connection,
    Keypair,
    PublicKey,
    Transaction,
    sendAndConfirmTransaction,
    ComputeBudgetProgram,
    SystemProgram,
    LAMPORTS_PER_SOL,
} from "@solana/web3.js";
import { NATIVE_MINT } from "@solana/spl-token";
import * as fs from "fs";

const PROGRAM_ID = new PublicKey("6u8921CKtcMbrR8sfHdc9M6V2NnymqCoKMLURtmivvxE");
const CHAINLINK_SOL_USD = new PublicKey("99B2bTijsU6f1GCT73HmdR7HCFFjGMBcPZY6jZ96ynrR");

// Smaller slab for 512 accounts instead of 4096
// SLAB_SIZE = ENGINE_OFF(392) + ENGINE_ACCOUNTS_OFF(9128) + 512 * 240 = 132,200 bytes
const SLAB_SIZE = 132200;

async function main() {
    console.log("\\n" + "=".repeat(70));
    console.log("PENNY PERPS: PRODUCTION MARKET (512 ACCOUNTS)");
    console.log("=".repeat(70));

    const walletPath = process.env.WALLET_PATH || `${process.env.HOME}/.config/solana/id.json`;
    const payer = Keypair.fromSecretKey(
        new Uint8Array(JSON.parse(fs.readFileSync(walletPath, "utf-8")))
    );
    const connection = new Connection("https://api.devnet.solana.com", "confirmed");

    console.log(`\\nProgram: ${PROGRAM_ID.toBase58()}`);
    console.log(`Wallet: ${payer.publicKey.toBase58()}`);
    const balance = await connection.getBalance(payer.publicKey);
    console.log(`Balance: ${(balance / LAMPORTS_PER_SOL).toFixed(4)} SOL`);

    // Create smaller slab
    console.log(`\\nStep 1: Creating slab (${SLAB_SIZE} bytes for 512 accounts)...`);
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

    const createSig = await sendAndConfirmTransaction(connection, createSlabTx, [payer, slab], { commitment: "confirmed" });
    console.log(`  Created: ${createSig}`);

    // Initialize market
    console.log("\\nStep 2: Initializing market...");

    const initData = Buffer.alloc(1);
    initData.writeUInt8(0, 0);

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
        skipPreflight: false,
    });

    console.log(`  Initialized: ${initSig}`);

    // Save market info
    const marketInfo = {
        network: "devnet",
        createdAt: new Date().toISOString(),
        programId: PROGRAM_ID.toBase58(),
        slab: slab.publicKey.toBase58(),
        slabSize: SLAB_SIZE,
        maxAccounts: 512,
        mint: NATIVE_MINT.toBase58(),
        oracle: CHAINLINK_SOL_USD.toBase58(),
        admin: payer.publicKey.toBase58(),
        createTx: createSig,
        initTx: initSig,
    };

    fs.writeFileSync("production-market.json", JSON.stringify(marketInfo, null, 2));

    console.log("\\n" + "=".repeat(70));
    console.log("✅ MARKET DEPLOYED SUCCESSFULLY!");
    console.log("=".repeat(70));
    console.log(`\\nSlab: ${slab.publicKey.toBase58()}`);
    console.log(`Max Accounts: 512`);
    console.log(`\\nMarket info saved to production-market.json`);
    console.log("=".repeat(70) + "\\n");
}

main().catch(console.error);
