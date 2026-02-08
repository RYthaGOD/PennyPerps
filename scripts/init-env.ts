
import fs from 'fs';
import path from 'path';
import os from 'os';
import { Keypair } from '@solana/web3.js';

const ENV_PATH = path.resolve(process.cwd(), '.env');
const KEY_DIR = path.join(os.homedir(), '.config', 'solana');
const KEY_PATH = path.join(KEY_DIR, 'id.json');

function main() {
    console.log('Initializing Environment...');

    // 1. Ensure Keypair exists
    if (!fs.existsSync(KEY_PATH)) {
        console.log(`Creating keypair at ${KEY_PATH}...`);
        fs.mkdirSync(KEY_DIR, { recursive: true });
        const kp = Keypair.generate();
        fs.writeFileSync(KEY_PATH, JSON.stringify(Array.from(kp.secretKey)));
        console.log(`✅ Keypair created: ${kp.publicKey.toBase58()}`);
    } else {
        console.log(`✅ Found existing keypair at ${KEY_PATH}`);
    }

    // 2. Ensure .env exists
    if (!fs.existsSync(ENV_PATH)) {
        console.log('Creating .env file...');
        const envContent = `SOLANA_RPC_URL=https://api.devnet.solana.com
WALLET_PATH=${KEY_PATH.replace(/\\/g, '/')}
# Percolator Devnet Program ID
PROGRAM_ID=2SSnp35m7FQ7cRLNKGdW5UzjYFF6RBUNq7d3m5mqNByp
`;
        fs.writeFileSync(ENV_PATH, envContent);
        console.log('✅ Created .env');
    } else {
        console.log('✅ Found existing .env');
    }

    console.log('\nEnvironment Setup Complete!');
}

main();
