
import "dotenv/config";
import { Connection, PublicKey } from "@solana/web3.js";
import * as fs from "fs";

const SLAB_PUBKEY = new PublicKey("GFoKxFAGm5NY5dvhmga6yiV1Bbr3qv9gfkJBcBexhGvj");

async function main() {
    const connection = new Connection("https://api.devnet.solana.com", "confirmed");
    const info = await connection.getAccountInfo(SLAB_PUBKEY);

    if (!info) {
        console.log("Slab not found!");
        return;
    }

    console.log(`Owner: ${info.owner.toBase58()}`);
    console.log(`Data Length: ${info.data.length}`);
    console.log(`First 16 bytes (hex): ${info.data.slice(0, 16).toString('hex')}`);
    console.log(`First 8 bytes (BigInt): ${info.data.readBigUInt64LE(0)}`);

    // Magic expected: 504552434f4c4154 (PERCOLAT)
    // Little endian: 54414c4f...

    console.log("Raw bytes:", info.data.slice(0, 16));
}

main().catch(console.error);
