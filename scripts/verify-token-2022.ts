
import "dotenv/config";
import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  sendAndConfirmTransaction,
  ComputeBudgetProgram,
  SYSVAR_CLOCK_PUBKEY,
  SYSVAR_RENT_PUBKEY,
} from "@solana/web3.js";
import {
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID, // <--- Added
  createMint,
  createAccount,
  mintTo,
  getOrCreateAssociatedTokenAccount
} from "@solana/spl-token";
import * as fs from "fs";
import { encodeInitMarket, encodeInitUser, encodeDepositCollateral } from "../src/abi/instructions.js";
import { buildAccountMetas, ACCOUNTS_INIT_MARKET, ACCOUNTS_INIT_USER, ACCOUNTS_DEPOSIT_COLLATERAL } from "../src/abi/accounts.js";
import { buildIx } from "../src/runtime/tx.js";
import { deriveVaultAuthority } from "../src/solana/pda.js";

const PROGRAM_ID = new PublicKey('2SSnp35m7FQ7cRLNKGdW5UzjYFF6RBUNq7d3m5mqNByp');

// Setup connection
const conn = new Connection(process.env.SOLANA_RPC_URL || 'https://api.devnet.solana.com', 'confirmed');
const admin = Keypair.fromSecretKey(
  Uint8Array.from(JSON.parse(fs.readFileSync(process.env.HOME + '/.config/solana/id.json', 'utf-8')))
);

async function main() {
  console.log("Verifying Standard SPL Token Support (Control Test)..."); // Updated message
  console.log(`Program: ${PROGRAM_ID.toBase58()}`);
  console.log(`Admin: ${admin.publicKey.toBase58()}`);

  // 1. Create a Standard SPL Token Mint (Control Test)
  console.log("\n1. Creating Standard SPL Token Mint (Control Test)..."); // Updated message
  const mintKp = Keypair.generate();
  const mint = await createMint(
    conn,
    admin,
    admin.publicKey,
    null,
    6,
    mintKp,
    undefined,
    TOKEN_PROGRAM_ID // Changed to Standard Token Program
  );
  console.log(`Standard Mint: ${mint.toBase58()}`); // Updated message

  // 2. Initialize Market with Standard Mint
  console.log("\n2. Initializing Market with Standard Mint..."); // Updated message
  const slabKp = Keypair.generate();
  const vaultKp = Keypair.generate();

  // Calculate reduced slab size for testing
  // Original: 992,568 bytes (~6.9 SOL rent)
  // We need to fit in < 2 SOL.
  // Header (392) + Bitmap (512) + Accounts (256 * 240) = 62,344 bytes
  // Rent for 62KB is much cheaper (~0.4 SOL)

  // To verify exact size:
  // ENGINE_OFF = 392
  // ENGINE_BITMAP_OFF = 408 (relative to engine start? No, in slab.ts it's offset from engine start)
  // Wait, let's look at slab.ts layout
  // ENGINE_OFF = 392
  // ENGINE_ACCOUNTS_OFF = 9136
  // Accounts start at 392 + 9136 = 9528
  // 256 accounts * 240 bytes = 61440
  // Total = 9528 + 61440 = 70968 bytes
  const slabSize = 70968;
  const slabRent = await conn.getMinimumBalanceForRentExemption(slabSize);
  console.log(`Slab Size: ${slabSize} bytes, Rent: ${slabRent / 1e9} SOL`);

  const createSlabIx = SystemProgram.createAccount({
    fromPubkey: admin.publicKey,
    newAccountPubkey: slabKp.publicKey,
    lamports: slabRent,
    space: slabSize,
    programId: PROGRAM_ID,
  });

  // Create vault account (Standard Token Program)
  // The vault must be owned by TOKEN_PROGRAM_ID for the initializeAccount instruction to work?
  // No, actually:
  // 1. Create Account (Owner = Token)
  // 2. Initialize Account (Mint, Authority = VaultAuth, Program = Token)

  const vaultRent = await conn.getMinimumBalanceForRentExemption(165);
  const createVaultIx = SystemProgram.createAccount({
    fromPubkey: admin.publicKey,
    newAccountPubkey: vaultKp.publicKey,
    lamports: vaultRent,
    space: 165,
    programId: TOKEN_PROGRAM_ID, // Changed to Standard Token Program
  });

  // Init vault token account
  const { createInitializeAccount3Instruction } = await import("@solana/spl-token");
  const [vaultAuth] = deriveVaultAuthority(PROGRAM_ID, slabKp.publicKey);

  console.log(`Vault: ${vaultKp.publicKey.toBase58()}`);
  console.log(`Vault Auth PDA: ${vaultAuth.toBase58()}`);

  const initVaultIx = createInitializeAccount3Instruction(
    vaultKp.publicKey,
    mint,
    vaultAuth,
    TOKEN_PROGRAM_ID // Changed to Standard Token Program
  );

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

  // Note: We pass TOKEN_PROGRAM_ID in the accounts list for control test
  const dummyAta = await getOrCreateAssociatedTokenAccount(conn, admin, mint, admin.publicKey, undefined, undefined, undefined, TOKEN_PROGRAM_ID);

  // ACCOUNTS_INIT_MARKET: [admin, slab, mint, vault, tokenProgram, clock, rent, _reserved_ata, systemProgram]
  // We need to ensure the 5th account (index 4) 'tokenProgram' is TOKEN_PROGRAM_ID

  const initMarketKeysRaw = [
    { pubkey: admin.publicKey, isSigner: true, isWritable: true },   // 0: admin
    { pubkey: slabKp.publicKey, isSigner: true, isWritable: true },  // 1: slab
    { pubkey: mint, isSigner: false, isWritable: false },            // 2: mint
    { pubkey: vaultKp.publicKey, isSigner: false, isWritable: true },// 3: vault
    { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false }, // 4: tokenProgram (Standard)
    { pubkey: SYSVAR_CLOCK_PUBKEY, isSigner: false, isWritable: false },   // 5: clock
    { pubkey: SYSVAR_RENT_PUBKEY, isSigner: false, isWritable: false },    // 6: rent
    { pubkey: dummyAta.address, isSigner: false, isWritable: false },      // 7: _reserved_ata
    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },// 8: systemProgram
  ];

  /*
  const initMarketKeys = buildAccountMetas(ACCOUNTS_INIT_MARKET, [
    admin.publicKey,
    slabKp.publicKey,
    mint,
    vaultKp.publicKey,
    TOKEN_2022_PROGRAM_ID, // <--- This was arguably correct if buildAccountMetas respects order
    SYSVAR_CLOCK_PUBKEY,
    SYSVAR_RENT_PUBKEY,
    dummyAta.address, 
    SystemProgram.programId,
  ]);
  */

  const tx = new Transaction().add(
    ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
    createSlabIx,
    createVaultIx,
    initVaultIx,
    buildIx({ programId: PROGRAM_ID, keys: initMarketKeysRaw, data: initMarketData }),
  );

  // Simulate first to get detailed logs
  console.log("Simulating InitMarket...");
  const sim = await conn.simulateTransaction(tx, [admin, slabKp, vaultKp]);
  if (sim.value.err) {
    console.error("Simulation Error:", sim.value.err);
    console.log("Logs:", sim.value.logs);
    return; // Stop on simulation failure
  }
  console.log("Simulation Success!");

  try {
    await sendAndConfirmTransaction(conn, tx, [admin, slabKp, vaultKp]);
    console.log("✅ InitMarket SUCCESS with Token-2022!");
  } catch (e: any) {
    console.log("❌ InitMarket FAILED with Token-2022");
    console.log(e.message || e);
    if (e.logs) console.log(e.logs);
    return; // Stop if market init fails
  }

  // 3. Init User & Deposit
  console.log("\n3. Testing Deposit with Token-2022...");

  // Mint some tokens to admin
  await mintTo(conn, admin, mint, dummyAta.address, admin, 1_000_000, [], undefined, TOKEN_2022_PROGRAM_ID);

  // Init User
  const initUserData = encodeInitUser({ feePayment: 0n });
  const initUserKeys = buildAccountMetas(ACCOUNTS_INIT_USER, [
    admin.publicKey,
    slabKp.publicKey,
    dummyAta.address, // User ATA
    vaultKp.publicKey,
    TOKEN_2022_PROGRAM_ID, // <--- Key Check
  ]);

  const initUserTx = new Transaction().add(
    buildIx({ programId: PROGRAM_ID, keys: initUserKeys, data: initUserData })
  );
  await sendAndConfirmTransaction(conn, initUserTx, [admin]);
  console.log("✅ InitUser SUCCESS");

  // Deposit
  const depositData = encodeDepositCollateral({ userIdx: 0, amount: 1_000_000n });
  const depositKeys = buildAccountMetas(ACCOUNTS_DEPOSIT_COLLATERAL, [
    admin.publicKey,
    slabKp.publicKey,
    dummyAta.address,
    vaultKp.publicKey,
    TOKEN_2022_PROGRAM_ID, // <--- Key Check
    SYSVAR_CLOCK_PUBKEY,
  ]);

  const depositTx = new Transaction().add(
    ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
    buildIx({ programId: PROGRAM_ID, keys: depositKeys, data: depositData })
  );

  try {
    await sendAndConfirmTransaction(conn, depositTx, [admin]);
    console.log("✅ Deposit SUCCESS with Token-2022!");
  } catch (e: any) {
    console.log("❌ Deposit FAILED with Token-2022");
    console.log(e.message || e);
    if (e.logs) console.log(e.logs);
  }
}

main().catch(console.error);
