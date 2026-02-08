import { readFileSync, existsSync } from "node:fs";
import { resolve, join } from "node:path";
import { z } from "zod";
import { Commitment } from "@solana/web3.js";
import os from "os";

const CommitmentSchema = z.enum(["processed", "confirmed", "finalized"]);

const ConfigSchema = z.object({
  rpcUrl: z.string().url(),
  programId: z.string().optional(),
  wallet: z.string(),
  commitment: CommitmentSchema.default("confirmed"),
});

export type Config = z.infer<typeof ConfigSchema>;

export interface GlobalFlags {
  config?: string;
  rpc?: string;
  program?: string;
  wallet?: string;
  commitment?: Commitment;
  json?: boolean;
  simulate?: boolean;
}

const DEFAULT_CONFIG_NAME = "percolator-cli.json";

/**
 * Load and validate config, with CLI flag overrides.
 */
export function loadConfig(flags: GlobalFlags): Config {
  // 1. Try to load from file
  const configPath = flags.config ?? findConfig();
  let fileConfig: Partial<Config> = {};

  if (configPath && existsSync(configPath)) {
    try {
      const raw = readFileSync(configPath, "utf-8");
      fileConfig = JSON.parse(raw);
    } catch (e) {
      throw new Error(`Failed to parse config file ${configPath}: ${e}`);
    }
  }

  // 2. Resolve wallet path (CLI > Env > File > Default)
  // Default on Windows: %USERPROFILE%/.config/solana/id.json
  // Default on Unix: ~/.config/solana/id.json
  const defaultWalletPath = join(os.homedir(), ".config", "solana", "id.json");

  const rawWalletPath =
    flags.wallet ??
    process.env.WALLET_PATH ??
    fileConfig.wallet ??
    defaultWalletPath;

  const wallet = expandPath(rawWalletPath);

  // 3. Merge everything
  const merged = {
    rpcUrl: flags.rpc ?? process.env.SOLANA_RPC_URL ?? fileConfig.rpcUrl ?? "https://api.devnet.solana.com",
    programId: flags.program ?? process.env.PROGRAM_ID ?? fileConfig.programId,
    wallet,
    commitment: flags.commitment ?? fileConfig.commitment ?? "confirmed",
  };

  // 4. Validate
  const result = ConfigSchema.safeParse(merged);
  if (!result.success) {
    const issues = result.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`);
    throw new Error(`Invalid config:\n${issues.join("\n")}`);
  }

  return result.data;
}

/**
 * Find config file in cwd.
 */
function findConfig(): string | undefined {
  const path = resolve(process.cwd(), DEFAULT_CONFIG_NAME);
  return existsSync(path) ? path : undefined;
}

/**
 * Expand ~ to home directory and resolve relative paths.
 */
export function expandPath(p: string): string {
  if (p.startsWith("~")) {
    return join(os.homedir(), p.slice(1));
  }
  return resolve(p);
}
