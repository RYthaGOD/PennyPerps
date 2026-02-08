import {
    Keypair,
    SystemProgram,
    PublicKey,
    Transaction,
    ComputeBudgetProgram
} from "@solana/web3.js";
import {
    TOKEN_2022_PROGRAM_ID,
    getOrCreateAssociatedTokenAccount
} from "@solana/spl-token";
import { MockPercolator } from "../src/mock/MockV3";
import { encodeInitMarket } from "../src/abi/instructions.js";
import { ACCOUNTS_INIT_MARKET, buildAccountMetas } from "../src/abi/accounts.js";
import { buildIx, simulateOrSend, formatResult } from "../src/runtime/tx.js";
import { deriveVaultAuthority } from "../src/solana/pda.js";

console.log("Testing Resurrected (Revert)...");
try {
    const mock = new MockPercolator("http://localhost:8899");
    console.log("MockPercolator initialized successfully.");

    console.log("SPL Token 2022 ID:", TOKEN_2022_PROGRAM_ID.toBase58());

    const admin = Keypair.generate();
    const slabKp = Keypair.generate();
    const mintKp = Keypair.generate();
    const vaultKp = Keypair.generate();
    const mint = mintKp.publicKey;

    const sysvarClock = Keypair.generate().publicKey; // Workaround
    const sysvarRent = Keypair.generate().publicKey; // Workaround
    const dummyAta = Keypair.generate().publicKey;
    const programIdKp = Keypair.generate();
    const PROGRAM_ID = programIdKp.publicKey;

    // Manual keys array
    const keys = [
        { pubkey: admin.publicKey, isSigner: true, isWritable: true },
        { pubkey: slabKp.publicKey, isSigner: true, isWritable: true },
        { pubkey: mint, isSigner: false, isWritable: false },
        { pubkey: vaultKp.publicKey, isSigner: false, isWritable: true },
        { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
        { pubkey: sysvarClock, isSigner: false, isWritable: false },
        { pubkey: sysvarRent, isSigner: false, isWritable: false },
        { pubkey: dummyAta, isSigner: false, isWritable: false },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ];

    const initMarketData = encodeInitMarket({
        admin: admin.publicKey,
        collateralMint: mint,
        indexFeedId: '0'.repeat(64),
        maxStalenessSecs: 3600n, confFilterBps: 500, invert: 0, unitScale: 0,
        initialMarkPriceE6: 1000000n, warmupPeriodSlots: 0n, maintenanceMarginBps: 500n,
        initialMarginBps: 1000n, tradingFeeBps: 10n, maxAccounts: 256n, newAccountFee: 0n,
        riskReductionThreshold: 10000n, maintenanceFeePerSlot: 0n, maxCrankStalenessSlots: 200n,
        liquidationFeeBps: 100n, liquidationFeeCap: 1000000n, liquidationBufferBps: 50n,
        minLiquidationAbs: 100n,
    });

    console.log("Testing simulateOrSend with Keys...");
    const ix = buildIx({
        programId: PROGRAM_ID,
        keys: keys,
        data: initMarketData
    });

    // const signer = Keypair.generate(); // Replaced by admin

    const result = await simulateOrSend({
        connection: mock as any as import("@solana/web3.js").Connection,
        ix,
        signers: [admin, slabKp],
        simulate: true
    });
    console.log("simulateOrSend executed successfully.");
    console.log("Logs:", result.logs);

    const logStr = result.logs.join("\n");
    if (logStr.includes("Validation SUCCESS: Token-2022 is supported")) {
        console.log("\n✅ VERIFIED: Token-2022 (Privacy Cash) is supported by Mock Protocol!");
    } else {
        console.log("\n❌ FAILED: Validation log missing.");
        throw new Error("Validation failed");
    }

} catch (e) {
    console.error("Failed:", e);
    process.exit(1);
}
