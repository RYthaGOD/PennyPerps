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
import { MockPercolator } from "../src/mock/MockPercolator";
import { encodeInitMarket } from "../src/abi/instructions.js";
import { ACCOUNTS_INIT_MARKET, buildAccountMetas } from "../src/abi/accounts.js";
import { buildIx, simulateOrSend, formatResult } from "../src/runtime/tx.js";
import { deriveVaultAuthority } from "../src/solana/pda.js";

// Constants
const PROGRAM_ID = new PublicKey("MockPercolator11111111111111111111111111111"); // Arbitrary mock ID
const SYSVAR_CLOCK_PUBKEY = new PublicKey("SysvarClock11111111111111111111111111111111");
const SYSVAR_RENT_PUBKEY = new PublicKey("SysvarRent11111111111111111111111111111111");

async function main() {
    console.log("Verifying Token-2022 Support (via Client-Side Simulation)...");

    // Use MockConnection instead of real Connection
    console.log("Initializing MockPercolator...");
    const conn = new MockPercolator("http://localhost:8899");

    const admin = Keypair.generate();
    console.log(`Admin: ${admin.publicKey.toBase58()}`);

    // 1. Mock Mint (we don't create it on-chain, just generate a key)
    const mintKp = Keypair.generate();
    const mint = mintKp.publicKey;
    console.log(`Token-2022 Mint: ${mint.toBase58()}`);

    // 2. Initialize Market Logic
    const slabKp = Keypair.generate();
    const vaultKp = Keypair.generate();

    // Derive vault authority
    const [vaultAuth] = deriveVaultAuthority(PROGRAM_ID, slabKp.publicKey);

    console.log(`Vault: ${vaultKp.publicKey.toBase58()}`);

    // Emulate init instructions
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

    // We skip actual spl-token init/mint calls because it's a mock connection 
    // that implies success for standard instructions unless we parse them.
    // We focus on the InitMarket instruction.

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
        maxAccounts: 256n, // Matches reduced slab size
        newAccountFee: 0n,
        riskReductionThreshold: 10000n,
        maintenanceFeePerSlot: 0n,
        maxCrankStalenessSlots: 200n,
        liquidationFeeBps: 100n,
        liquidationFeeCap: 1_000_000n,
        liquidationBufferBps: 50n,
        minLiquidationAbs: 100n,
    });

    // Construction with Token-2022 explicitly
    const initMarketKeysRaw = [
        { pubkey: admin.publicKey, isSigner: true, isWritable: true },
        { pubkey: slabKp.publicKey, isSigner: true, isWritable: true },
        { pubkey: mint, isSigner: false, isWritable: false },
        { pubkey: vaultKp.publicKey, isSigner: false, isWritable: true },
        { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false }, // <--- The verification target
        { pubkey: SYSVAR_CLOCK_PUBKEY, isSigner: false, isWritable: false },
        { pubkey: SYSVAR_RENT_PUBKEY, isSigner: false, isWritable: false },
        { pubkey: Keypair.generate().publicKey, isSigner: false, isWritable: false }, // dummyAta
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ];

    const tx = new Transaction().add(
        ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
        createSlabIx,
        createVaultIx,
        buildIx({ programId: PROGRAM_ID, keys: initMarketKeysRaw, data: initMarketData }),
    );

    console.log("Sending Transaction to Mock Protocol...");

    try {
        const result = await simulateOrSend({
            connection: conn as any as import("@solana/web3.js").Connection,
            ix: buildIx({ programId: PROGRAM_ID, keys: initMarketKeysRaw, data: initMarketData }), // Just send the main Ix for simplicity or full tx?
            // simulateOrSend builds its own transaction. Let's pass the IX.
            signers: [admin, slabKp],
            simulate: false, // Send (which calls simulate internally in MockConnection)
            commitment: "confirmed"
        });

        console.log("\n--- RESULT ---");
        console.log(formatResult(result, false));

        const logs = result.logs.join("\n");
        if (logs.includes("Validation SUCCESS: Token-2022 is supported")) {
            console.log("\n✅ SUCCESS: Mock Protocol Verified Token-2022 Compatibility!");
        } else {
            console.log("\n❌ FAIL: Verification log missing.");
        }

    } catch (e: any) {
        console.error("Exec Failed:", e);
    }
}

main();
