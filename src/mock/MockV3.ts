console.log("LOADING MOCK V3");

export class MockPercolator {
    private slabs: Map<string, any> = new Map();
    private logs: string[] = [];

    constructor(endpoint: string, commitmentOrConfig?: any) {
    }

    async getMinimumBalanceForRentExemption(len: number, c?: any) { return len * 10; }
    async getLatestBlockhash(c?: any) {
        return { blockhash: "MockBlockhash11111111111111111111111111111111", lastValidBlockHeight: 1000 };
    }

    async simulateTransaction(tx: any, signers?: any[]) {
        this.logs = [];
        const instructions = tx.instructions;
        for (const ix of instructions) {
            this.logs.push(`Processing instruction for ${ix.programId.toBase58()}`);
            if (ix.data[0] === 0) {
                this.logs.push("Instruction: InitMarket");
                const tokenProgram = ix.keys[4].pubkey;
                this.logs.push(`Token Program: ${tokenProgram.toBase58()}`);

                if (tokenProgram.toBase58() === "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb") {
                    this.logs.push("Log: ✅ Validation SUCCESS: Token-2022 is supported by Mock Protocol.");
                }
            }
        }
        return {
            context: { slot: 1 },
            value: { err: null, logs: this.logs }
        };
    }

    async sendTransaction(tx: any, signers: any[], opts?: any) {
        const sim = await this.simulateTransaction(tx, signers);
        if (sim.value.err) throw new Error(JSON.stringify(sim.value.err));
        return "MockSignature1111111111111111111111111111111111";
    }

    async confirmTransaction(strat: any, com?: any) { return { value: { err: null } }; }
    async getTransaction(sig: string, opts?: any) { return { slot: 1, meta: { logMessages: this.logs, err: null } }; }
}
