import {
    Keypair,
    SystemProgram,
    PublicKey,
    Transaction,
    ComputeBudgetProgram
} from "@solana/web3.js";
import {
    TOKEN_2022_PROGRAM_ID
} from "@solana/spl-token";
import { MockPercolator } from "../src/mock/MockPercolatorV2";
import { encodeInitMarket } from "../src/abi/instructions.js";
import { buildIx, simulateOrSend } from "../src/runtime/tx.js";

// Top-level execution to match working test script
console.log("Verifying Token-2022 Support (via Client-Side Simulation)...");

try {
    // 1. Initialize logic
    console.log("Initializing MockPercolator...");
    const conn = new MockPercolator("http://localhost:8899");
    console.log("MockPercolator Initialized.");

    const PROGRAM_ID = new PublicKey("11111111111111111111111111111111");
    const SYSVAR_CLOCK_PUBKEY = new PublicKey("SysvarClock11111111111111111111111111111111");
    const SYSVAR_RENT_PUBKEY = new PublicKey("SysvarRent11111111111111111111111111111111");
    console.log("Pubkeys Initialized.");

    const admin = Keypair.generate();
    console.log(`Admin: ${admin.publicKey.toBase58()}`);

    // 2. Mock Mint
    const mintKp = Keypair.generate();
    const mint = mintKp.publicKey;
    console.log(`Token-2022 Mint: ${mint.toBase58()}`);

    // 3. Initialize Market Logic
    const slabKp = Keypair.generate();
    const vaultKp = Keypair.generate();

    console.log(`Vault: ${vaultKp.publicKey.toBase58()}`);

    const createSlabIx = SystemProgram.createAccount({
        fromPubkey: admin.publicKey,
        newAccountPubkey: slabKp.publicKey,
        lamports: 1000,
        space: 70968,
        programId: PROGRAM_ID,
    });

    const createVaultIx = SystemProgram.createAccount({
        fromPubkey: admin.publicKey,
        newAccountPubkey: vaultKp.publicKey,
        lamports: 100,
        space: 165,
        programId: TOKEN_2022_PROGRAM_ID,
    });

    const initMarketData = encodeInitMarket({
        admin: admin.publicKey,
        collateralMint: mint,
        indexFeedId: '0'.repeat(64),
        maxStalenessSecs: 3600n,
        confFilterBps: 500,
        invert: 0,
        unitScale: 0,
        initialMarkPriceE6: 1_000_000n,
        warmupPeriodSlots: 0n,
        maintenanceMarginBps: 500n,
        initialMarginBps: 1000n,
        tradingFeeBps: 10n,
        maxAccounts: 256n,
        newAccountFee: 0n,
        riskReductionThreshold: 10000n,
        maintenanceFeePerSlot: 0n,
        maxCrankStalenessSlots: 200n,
        liquidationFeeBps: 100n,
        liquidationFeeCap: 1_000_000n,
        liquidationBufferBps: 50n,
        minLiquidationAbs: 100n,
    });

    const initMarketKeysRaw = [
        { pubkey: admin.publicKey, isSigner: true, isWritable: true },
        { pubkey: slabKp.publicKey, isSigner: true, isWritable: true },
        { pubkey: mint, isSigner: false, isWritable: false },
        { pubkey: vaultKp.publicKey, isSigner: false, isWritable: true },
        { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
        { pubkey: SYSVAR_CLOCK_PUBKEY, isSigner: false, isWritable: false },
        { pubkey: SYSVAR_RENT_PUBKEY, isSigner: false, isWritable: false },
        { pubkey: Keypair.generate().publicKey, isSigner: false, isWritable: false },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ];

    console.log("Sending Transaction to Mock Protocol...");

    // We can use await at top-level in module
    const result = await simulateOrSend({
        connection: conn as any as import("@solana/web3.js").Connection,
        ix: buildIx({ programId: PROGRAM_ID, keys: initMarketKeysRaw, data: initMarketData }),
        signers: [admin, slabKp],
        simulate: false,
        commitment: "confirmed"
    });

    console.log("\n--- RESULT ---");
    console.log("Logs:", result.logs);

    const logs = result.logs.join("\n");
    if (logs.includes("Validation SUCCESS: Token-2022 is supported")) {
        console.log("\n✅ SUCCESS: Mock Protocol Verified Token-2022 Compatibility!");
    } else {
        console.log("\n❌ FAIL: Verification log missing.");
    }

} catch (e) {
    console.error("Exec Failed:", e);
}
