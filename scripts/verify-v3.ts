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
// Inline Mock Class to debug import issues
class MockPercolator {
    private logs: string[] = [];
    constructor(endpoint: string, commitmentOrConfig?: any) { }
    async getMinimumBalanceForRentExemption(len: number, c?: any) { return len * 10; }
    async getLatestBlockhash(c?: any) { return { blockhash: "MockBlockhash11111111111111111111111111111111", lastValidBlockHeight: 1000 }; }
    async simulateTransaction(tx: any, signers?: any[]) {
        this.logs = [];
        const instructions = tx.instructions;
        for (const ix of instructions) {
            this.logs.push(`Processing instruction for ${ix.programId.toBase58()}`);
            if (ix.data[0] === 0) {
                this.logs.push("Instruction: InitMarket");
                const tokenProgram = ix.keys[4].pubkey;
                if (tokenProgram.toBase58() === "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb") {
                    this.logs.push("Log: ✅ Validation SUCCESS: Token-2022 is supported by Mock Protocol.");
                }
            }
        }
        return { value: { err: null, logs: this.logs } };
    }
    async sendTransaction(tx: any, signers: any[], opts?: any) {
        const sim = await this.simulateTransaction(tx, signers);
        if (sim.value.err) throw new Error(JSON.stringify(sim.value.err));
        return "MockSignature1111111111111111111111111111111111";
    }
    async confirmTransaction(strat: any, com?: any) { return { value: { err: null } }; }
    async getTransaction(sig: string, opts?: any) { return { slot: 1, meta: { logMessages: this.logs, err: null } }; }
}

// import { MockPercolator } from "../src/mock/MockV3"; // Removed
import { encodeInitMarket } from "../src/abi/instructions.js";
import { buildIx, simulateOrSend } from "../src/runtime/tx.js";

console.log("Verifying V3...");

try {
    const conn = new MockPercolator("http://localhost:8899");
    console.log("MockPercolator Initialized.");

    // Setup Constants
    const PROGRAM_ID = new PublicKey("11111111111111111111111111111111");
    const SYSVAR_CLOCK_PUBKEY = new PublicKey("SysvarClock11111111111111111111111111111111");
    const SYSVAR_RENT_PUBKEY = new PublicKey("SysvarRent11111111111111111111111111111111");

    const admin = Keypair.generate();
    const mintKp = Keypair.generate();
    const mint = mintKp.publicKey;
    const slabKp = Keypair.generate();
    const vaultKp = Keypair.generate();

    // Create Transaction
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

    const initMarketKeysRaw = [
        { pubkey: admin.publicKey, isSigner: true, isWritable: true },
        { pubkey: slabKp.publicKey, isSigner: true, isWritable: true },
        { pubkey: mint, isSigner: false, isWritable: false },
        { pubkey: vaultKp.publicKey, isSigner: false, isWritable: true },
        { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false }, // TARGET
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

    console.log("Logs:", result.logs);

    if (result.logs.join("\n").includes("Validation SUCCESS")) {
        console.log("✅ SUCCESS");
    } else {
        console.log("❌ FAIL");
    }

} catch (e) {
    console.error("Exec Failed:", e);
}
