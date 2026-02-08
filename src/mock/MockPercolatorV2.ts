// No imports from web3.js to avoid circular deps
// import { Connection, ... } from "@solana/web3.js";

export class MockPercolator {
    private slabs: Map<string, any> = new Map();
    private logs: string[] = [];

    constructor(endpoint: string, commitmentOrConfig?: any) {
    }

    async getMinimumBalanceForRentExemption(
        dataLength: number,
        commitment?: any
    ): Promise<number> {
        return dataLength * 10;
    }

    async getLatestBlockhash(commitment?: any): Promise<any> {
        return {
            blockhash: "MockBlockhash11111111111111111111111111111111",
            lastValidBlockHeight: 1000,
        };
    }

    async simulateTransaction(
        transaction: any, // Typed as any
        signers?: any[]
    ): Promise<any> {
        this.logs = [];
        const instructions = transaction.instructions;

        for (const ix of instructions) {
            this.logs.push(`Processing instruction for ${ix.programId.toBase58()}`);
            if (ix.data[0] === 0) {
                this.logs.push("Instruction: InitMarket");
                if (ix.keys.length < 5) {
                    this.logs.push("Error: Not enough keys");
                    return this.mockError("Not enough keys");
                }
                const mint = ix.keys[2].pubkey;
                const tokenProgram = ix.keys[4].pubkey;
                this.logs.push(`Mint: ${mint.toBase58()}`);
                this.logs.push(`Token Program Passed: ${tokenProgram.toBase58()}`);
                if (tokenProgram.toBase58() === "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA") {
                    this.logs.push("Log: Standard SPL Token detected.");
                } else if (tokenProgram.toBase58() === "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb") {
                    this.logs.push("Log: Token-2022 (Privacy Cash) detected.");
                    this.logs.push("Log: ✅ Validation SUCCESS: Token-2022 is supported by Mock Protocol.");
                } else {
                    this.logs.push(`Error: Unknown Token Program ${tokenProgram.toBase58()}`);
                }
                this.logs.push("Program log: Market initialized successfully (Mock)");
            }
        }
        return {
            context: { slot: 1 },
            value: {
                err: null,
                logs: this.logs,
                accounts: null,
                unitsConsumed: 100,
                returnData: null,
            },
        };
    }

    async sendTransaction(
        transaction: any,
        signers: any[],
        options?: any
    ): Promise<string> {
        const sim = await this.simulateTransaction(transaction, signers);
        if (sim.value.err) {
            throw new Error("Simulation failed: " + JSON.stringify(sim.value.err));
        }
        return "MockSignature1111111111111111111111111111111111";
    }

    async confirmTransaction(
        strategy: any,
        commitment?: any
    ): Promise<any> {
        return {
            context: { slot: 1 },
            value: { err: null },
        };
    }

    async getTransaction(signature: string, options?: any) {
        return {
            slot: 1,
            meta: {
                logMessages: this.logs,
                err: null
            }
        }
    }

    private mockError(msg: string): any {
        return {
            context: { slot: 1 },
            value: {
                err: { InstructionError: [0, { Custom: 1 }] },
                logs: this.logs,
                accounts: null,
                unitsConsumed: 0,
                returnData: null
            }
        }
    }
}
