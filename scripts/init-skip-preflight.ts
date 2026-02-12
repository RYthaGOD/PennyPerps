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

async function main() {
    console.log("\\n" + "=".repeat(70));
    console.log("PENNY PERPS: MARKET INIT (SKIP PREFLIGHT)");
    console.log("=".repeat(70));

    const walletPath = process.env.WALLET_PATH || `${process.env.HOME}/.config/solana/id.json`;
    const payer = Keypair.fromSecretKey(
        new Uint8Array(JSON.parse(fs.readFileSync(walletPath, "utf-8")))
    );
    const connection = new Connection("https://api.devnet.solana.com", "confirmed");

    console.log(`\\nProgram: ${PROGRAM_ID.toBase58()}`);
    console.log(`Slab: ${EXISTING_SLAB.toBase58()}`);

    const initData = Buffer.alloc(1);
    initData.writeUInt8(0, 0);

    const initTx = new Transaction();
    initTx.add(ComputeBudgetProgram.setComputeUnitLimit({ units: 50000 })); // Lower CU for optimized version
    initTx.add({
        programId: PROGRAM_ID,
        keys: [
            { pubkey: payer.publicKey, isSigner: true, isWritable: true },
            { pubkey: EXISTING_SLAB, isSigner: false, isWritable: true },
        ],
        data: initData,
    });

    console.log("\\nSending transaction (skipPreflight=true)...");
    const sig = await sendAndConfirmTransaction(connection, initTx, [payer], {
        commitment: "confirmed",
        skipPreflight: true, // Skip simulation, execute directly
    });

    console.log(`\\n✅ Transaction sent: ${sig}`);
    console.log("Waiting for confirmation...");

    await new Promise(resolve => setTimeout(resolve, 2000));

    const status = await connection.getSignatureStatus(sig);
    console.log("Status:", JSON.stringify(status, null, 2));

    if (status.value?.err) {
        console.error("Transaction failed:", status.value.err);
    } else {
        console.log("\\n✅ SUCCESS! Market initialized!");

        const marketInfo = {
            network: "devnet",
            createdAt: new Date().toISOString(),
            programId: PROGRAM_ID.toBase58(),
            slab: EXISTING_SLAB.toBase58(),
            mint: NATIVE_MINT.toBase58(),
            initTx: sig,
        };

        fs.writeFileSync("production-market.json", JSON.stringify(marketInfo, null, 2));
        console.log("Market info saved to production-market.json");
    }
}

main().catch(console.error);
