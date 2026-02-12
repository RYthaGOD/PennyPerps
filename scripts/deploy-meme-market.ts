/**
 * deploy-meme-market.ts
 * 
 * Deploys a Hyperp meme coin market (e.g. PEPE-PERP) on devnet.
 * Hyperp markets use a fixed price controllable by the admin/crank,
 * making them ideal for high-volatility meme coins where oracles may not exist.
 */

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
    SYSVAR_RENT_PUBKEY,
    LAMPORTS_PER_SOL,
} from "@solana/web3.js";
import {
    getOrCreateAssociatedTokenAccount,
    TOKEN_PROGRAM_ID,
    NATIVE_MINT,
} from "@solana/spl-token";
import * as fs from "fs";
import {
    encodeInitMarket,
    encodeInitLP,
    encodeDepositCollateral,
} from "../src/abi/instructions.js";
import {
    ACCOUNTS_INIT_MARKET,
    ACCOUNTS_INIT_LP,
    ACCOUNTS_DEPOSIT_COLLATERAL,
    buildAccountMetas,
} from "../src/abi/accounts.js";
import { deriveVaultAuthority } from "../src/solana/pda.js";
import { parseUsedIndices } from "../src/solana/slab.js";
import { buildIx } from "../src/runtime/tx.js";

const PROGRAM_ID = new PublicKey("Perco1ator111111111111111111111111111111111");
const SLAB_SIZE = 992560;

async function main() {
    const walletPath = process.env.WALLET_PATH || `${process.env.HOME}/.config/solana/id.json`;
    const payer = Keypair.fromSecretKey(
        new Uint8Array(JSON.parse(fs.readFileSync(walletPath, "utf-8")))
    );
    const connection = new Connection("https://api.devnet.solana.com", "confirmed");

    console.log(`Payer: ${payer.publicKey.toBase58()}`);

    const mint = NATIVE_MINT; // Use WSOL as collateral
    const slab = Keypair.generate();
    const rentExempt = await connection.getMinimumBalanceForRentExemption(SLAB_SIZE);

    console.log(`Creating Slab: ${slab.publicKey.toBase58()}`);
    const createSlabTx = new Transaction().add(
        SystemProgram.createAccount({
            fromPubkey: payer.publicKey,
            newAccountPubkey: slab.publicKey,
            lamports: rentExempt,
            space: SLAB_SIZE,
            programId: PROGRAM_ID,
        })
    );
    await sendAndConfirmTransaction(connection, createSlabTx, [payer, slab]);

    const [vaultPda] = deriveVaultAuthority(PROGRAM_ID, slab.publicKey);
    const vaultAccount = await getOrCreateAssociatedTokenAccount(connection, payer, mint, vaultPda, true);
    const vault = vaultAccount.address;

    console.log("Initializing Hyperp Meme Market (Initial Price: $0.000015)");
    const initMarketData = encodeInitMarket({
        admin: payer.publicKey,
        collateralMint: mint,
        indexFeedId: "00".repeat(32), // No oracle for Hyperp
        maxStalenessSecs: "3600",
        confFilterBps: 0,
        invert: 0,
        unitScale: 0,
        initialMarkPriceE6: "15", // $0.000015
        warmupPeriodSlots: "5",
        maintenanceMarginBps: "1000", // 10%
        initialMarginBps: "2000",    // 20%
        tradingFeeBps: "20",         // 0.2%
        maxAccounts: "1024",
        newAccountFee: "1000000",
        riskReductionThreshold: "0",
        maintenanceFeePerSlot: "0",
        maxCrankStalenessSlots: "200",
        liquidationFeeBps: "200",
        liquidationFeeCap: "100000000",
        liquidationBufferBps: "100",
        minLiquidationAbs: "10000",
    });

    const initMarketKeys = buildAccountMetas(ACCOUNTS_INIT_MARKET, [
        payer.publicKey,
        slab.publicKey,
        mint,
        vault,
        TOKEN_PROGRAM_ID,
        SYSVAR_CLOCK_PUBKEY,
        SYSVAR_RENT_PUBKEY,
        vaultPda,
        SystemProgram.programId,
    ]);

    const initTx = new Transaction().add(
        buildIx({ programId: PROGRAM_ID, keys: initMarketKeys, data: initMarketData })
    );
    await sendAndConfirmTransaction(connection, initTx, [payer]);

    console.log("Market Deployed Successfully.");
    const marketInfo = {
        ticker: "PEPE-PERP",
        slab: slab.publicKey.toBase58(),
        vault: vault.toBase58(),
        programId: PROGRAM_ID.toBase58(),
        admin: payer.publicKey.toBase58(),
    };
    fs.writeFileSync("meme-market.json", JSON.stringify(marketInfo, null, 2));
}

main().catch(console.error);
