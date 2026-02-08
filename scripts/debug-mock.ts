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

async function main() {
    console.log("Debug Start.");
    try {
        const PROGRAM_ID = new PublicKey("11111111111111111111111111111111");
        console.log("PublicKey OK.");

        // const conn = new MockPercolator("http://localhost:8899");
        // console.log("MockPercolator OK.");
        const SYSVAR_CLOCK_PUBKEY = new PublicKey("SysvarClock11111111111111111111111111111111");
        const SYSVAR_RENT_PUBKEY = new PublicKey("SysvarRent11111111111111111111111111111111");
        console.log("Pubkeys OK.");

        /*
        const admin = Keypair.generate();
        const mintKp = Keypair.generate();
        const mint = mintKp.publicKey;
        const slabKp = Keypair.generate();
        const vaultKp = Keypair.generate();

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

        console.log("Sending Transaction...");

        const result = await simulateOrSend({
            connection: conn as any as import("@solana/web3.js").Connection,
            ix: buildIx({ programId: PROGRAM_ID, keys: initMarketKeysRaw, data: initMarketData }),
            signers: [admin, slabKp],
            simulate: false,
            commitment: "confirmed"
        });

        console.log("Result Logs:", result.logs);
        const logs = result.logs.join("\n");
        if (logs.includes("Validation SUCCESS: Token-2022 is supported")) {
            console.log("✅ CHECK PASSED");
        } else {
            console.log("❌ CHECK FAILED");
        }
        */
        console.log("Logic commented out.");

    } catch (e) {
        console.error("Exec Failed:", e);
    }
}
main();
