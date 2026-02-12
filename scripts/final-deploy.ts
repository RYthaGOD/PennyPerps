import "dotenv/config";
import {
    Connection,
    Keypair,
    PublicKey,
    Transaction,
    sendAndConfirmTransaction,
    ComputeBudgetProgram,
    SYSVAR_CLOCK_PUBKEY,
    LAMPORTS_PER_SOL,
} from "@solana/web3.js";
import { NATIVE_MINT } from "@solana/spl-token";
import * as fs from "fs";
import {
    encodeInitMarket,
    encodeKeeperCrank,
} from "../src/abi/instructions.js";
import {
    ACCOUNTS_INIT_MARKET,
    ACCOUNTS_KEEPER_CRANK,
    buildAccountMetas,
} from "../src/abi/accounts.js";
import { buildIx } from "../src/runtime/tx.js";

const PROGRAM_ID = new PublicKey("6u8921CKtcMbrR8sfHdc9M6V2NnymqCoKMLURtmivvxE");
const EXISTING_SLAB = new PublicKey("FZnRiTQZqtJ2rttfZD6T8HvNmAopvjQz9a3xng7t8ihA"); // 132KB slab we already paid for
const CHAINLINK_SOL_USD = new PublicKey("99B2bTijsU6f1GCT73HmdR7HCFFjGMBcPZY6jZ96ynrR");

async function main() {
    console.log("\\n" + "=".repeat(70));
    console.log("FINAL DEVNET DEPLOYMENT");
    console.log("=".repeat(70));

    const walletPath = process.env.WALLET_PATH || `${process.env.HOME}/.config/solana/id.json`;
    const payer = Keypair.fromSecretKey(
        new Uint8Array(JSON.parse(fs.readFileSync(walletPath, "utf-8")))
    );
    const connection = new Connection("https://api.devnet.solana.com", "confirmed");

    console.log(`\\nProgram: ${PROGRAM_ID.toBase58()}`);
    console.log(`Slab: ${EXISTING_SLAB.toBase58()}`);
    console.log(`Wallet: ${payer.publicKey.toBase58()}`);

    // Initialize market using reference implementation's instruction encoder
    console.log("\\nInitializing market...");

    const initData = encodeInitMarket({
        admin: payer.publicKey,
        collateralMint: NATIVE_MINT,
        indexFeedId: Buffer.from(CHAINLINK_SOL_USD.toBytes()).toString("hex"),
        maxStalenessSecs: "3600",
        confFilterBps: 500,
        invert: 1,
        unitScale: 0,
        initialMarkPriceE6: "0",
        warmupPeriodSlots: "10",
        maintenanceMarginBps: "500",
        initialMarginBps: "1000",
        tradingFeeBps: "10",
        maxAccounts: "512",
        newAccountFee: "1000000",
        riskReductionThreshold: "0",
        maintenanceFeePerSlot: "0",
        maxCrankStalenessSlots: "200",
        liquidationFeeBps: "100",
        liquidationFeeCap: "1000000000",
        liquidationBufferBps: "50",
        minLiquidationAbs: "100000",
    });

    const initKeys = buildAccountMetas(ACCOUNTS_INIT_MARKET, [
        payer.publicKey,
        EXISTING_SLAB,
        NATIVE_MINT,
        PublicKey.default, // vault (will be derived)
        PublicKey.default, // token program
        SYSVAR_CLOCK_PUBKEY,
        PublicKey.default, // rent
        PublicKey.default, // vault authority
        PublicKey.default, // system program
    ]);

    const initTx = new Transaction();
    initTx.add(ComputeBudgetProgram.setComputeUnitLimit({ units: 400000 }));
    initTx.add(buildIx({ programId: PROGRAM_ID, keys: initKeys, data: initData }));

    const sig = await sendAndConfirmTransaction(connection, initTx, [payer], {
        commitment: "confirmed",
        skipPreflight: true,
    });

    console.log(`✅ Market initialized: ${sig}`);

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
    console.log("\\n✅ DEPLOYMENT COMPLETE!");
    console.log("Market info saved to production-market.json\\n");
}

main().catch(console.error);
