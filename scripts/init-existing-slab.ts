import "dotenv/config";
import {
    Connection,
    Keypair,
    PublicKey,
    Transaction,
    sendAndConfirmTransaction,
    ComputeBudgetProgram,
} from "@solana/web3.js";
import { NATIVE_MINT } from "@solana/spl-token";
import * as fs from "fs";

const PROGRAM_ID = new PublicKey("6u8921CKtcMbrR8sfHdc9M6V2NnymqCoKMLURtmivvxE");
const EXISTING_SLAB = new PublicKey("7yDwCXkspKBmPKR9ojcYUMfkK2cs7PgBnPtDEueiLMN4");
const CHAINLINK_SOL_USD = new PublicKey("99B2bTijsU6f1GCT73HmdR7HCFFjGMBcPZY6jZ96ynrR");

async function main() {
    console.log("\\n" + "=".repeat(70));
    console.log("PENNY PERPS: INITIALIZING EXISTING SLAB");
    console.log("=".repeat(70));

    const walletPath = process.env.WALLET_PATH || `${process.env.HOME}/.config/solana/id.json`;
    const payer = Keypair.fromSecretKey(
        new Uint8Array(JSON.parse(fs.readFileSync(walletPath, "utf-8")))
    );
    const connection = new Connection("https://api.devnet.solana.com", "confirmed");

    console.log(`\\nProgram: ${PROGRAM_ID.toBase58()}`);
    console.log(`Slab: ${EXISTING_SLAB.toBase58()}`);
    console.log(`Wallet: ${payer.publicKey.toBase58()}`);

    // Initialize market with MAX compute units
    console.log("\\nInitializing market (this may take a moment due to slab zeroing)...");

    const initData = Buffer.alloc(1);
    initData.writeUInt8(0, 0); // InitMarket tag

    const initTx = new Transaction();
    initTx.add(ComputeBudgetProgram.setComputeUnitLimit({ units: 1400000 })); // Max CUs
    initTx.add(ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1 })); // Priority fee
    initTx.add({
        programId: PROGRAM_ID,
        keys: [
            { pubkey: payer.publicKey, isSigner: true, isWritable: true },
            { pubkey: EXISTING_SLAB, isSigner: false, isWritable: true },
        ],
        data: initData,
    });

    const sig = await sendAndConfirmTransaction(connection, initTx, [payer], {
        commitment: "confirmed",
        skipPreflight: false,
    });

    console.log(`\\n✅ Market initialized!`);
    console.log(`Transaction: ${sig}`);

    // Save market info
    const marketInfo = {
        network: "devnet",
        createdAt: new Date().toISOString(),
        programId: PROGRAM_ID.toBase58(),
        slab: EXISTING_SLAB.toBase58(),
        mint: NATIVE_MINT.toBase58(),
        oracle: CHAINLINK_SOL_USD.toBase58(),
        admin: payer.publicKey.toBase58(),
        initTx: sig,
    };

    fs.writeFileSync("production-market.json", JSON.stringify(marketInfo, null, 2));
    console.log("\\nMarket info saved to production-market.json");
    console.log("\\n" + "=".repeat(70));
    console.log("SUCCESS!");
    console.log("=".repeat(70) + "\\n");
}

main().catch(console.error);
