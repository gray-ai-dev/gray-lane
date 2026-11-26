import type { SettingSpec, TextCrossCheck } from "./index.ts";

/**
 * Stablecoin deposits (track B2): the chains and tokens Gray credits, and the vars gray-jobs (the watcher and the
 * sweeper) and gray-console (the deposit address and history) read. gray-credit-signer's MinterDO checks every
 * deposit again against its own copy of the production list (workers/credit/src/lib/chain.ts
 * PRODUCTION_DEPOSIT_TOKENS; test/deposit.test.ts holds the two equal).
 *
 * EVM only. Production takes the tokens of PRODUCTION_DEPOSIT_TOKENS and nothing else (review §3.2): Base USDC (not the
 * bridged Base USDT), Ethereum USDC and USDT, BSC USDC and USDT, MegaETH mainnet USDm (not USDT0). A test chain's
 * token may be listed outside production. The MegaETH testnet (6343, where the production ledger lives) and the
 * Solana devnet id (900002) are refused in production: test tokens there are free.
 *
 * Kept apart from index.ts as ledger.ts is; index.ts appends the rows and the checks.
 */

/** One token Gray credits deposits of: its chain, its contract (lower case), its symbol and decimals. */
export interface DepositToken {
  readonly chainId: number;
  readonly address: string;
  readonly symbol: string;
  readonly decimals: number;
}

/** What Gray knows of a source chain. */
export interface DepositChain {
  readonly chainId: number;
  /** Shown to customers. */
  readonly name: string;
  /** The Worker secret holding the chain's JSON-RPC URL (gray-jobs and gray-credit-signer each have their own). */
  readonly rpcSecret: string;
  /**
   * Blocks a deposit must also lie below `latest` by, on top of the `finalized` tag (BSC: 15, review §3.3 keeps it
   * though BSC's fast finality makes it moot).
   */
  readonly extraDepth: number;
  /** The least balance, in micro-USD, the sweeper sweeps from one deposit address of this chain. */
  readonly sweepMinMicrousd: number;
  /** About how long a deposit takes to be final, in seconds, for the console to say. */
  readonly finalitySeconds: number;
}

/** Every deposit is credited from $1 (review §3.5): one rule on every chain, nothing below it is ever minted or summed. */
export const DEPOSIT_MIN_MICROUSD = 1_000_000;

/**
 * The most one deposit is credited by: GrayCredit's single-mint cap `caps.maxMintAmount` as deployed
 * (contracts/script/Deploy.s.sol defaultCaps, $10,000; gray-jobs' test/deposit-artifact.test.ts holds the two equal).
 * A deposit's mint is the whole transfer and cannot be split, so the watcher holds a larger one (held_over_cap) instead
 * of requesting a mint the contract refuses. DEPOSIT_MAX_MICROUSD may lower it, never raise it.
 */
export const DEPOSIT_CONTRACT_MAX_MICROUSD = 10_000_000_000;

/** The credited amount of a transfer: micro-USD, rounded down (`rawAmount / 10^(decimals - 6)`). */
export function depositMicrousd(rawAmount: bigint, decimals: number): bigint {
  if (!Number.isInteger(decimals) || decimals < 6 || decimals > 18) throw new Error(`token decimals ${decimals} are not 6 to 18`);
  return rawAmount / 10n ** BigInt(decimals - 6);
}

/**
 * The production tokens, checked on chain (`decimals()` at `latest` on the chains' public RPCs, 2026-11-24). Canonical
 * issuers only: Circle's USDC on Ethereum and Base, Tether's USDT on Ethereum, Binance-Peg USDC and USDT on BSC,
 * MegaETH's USDm.
 */
export const PRODUCTION_DEPOSIT_TOKENS: readonly DepositToken[] = [
  { chainId: 1, address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", symbol: "USDC", decimals: 6 },
  { chainId: 1, address: "0xdac17f958d2ee523a2206206994597c13d831ec7", symbol: "USDT", decimals: 6 },
  { chainId: 8453, address: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", symbol: "USDC", decimals: 6 },
  { chainId: 56, address: "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d", symbol: "USDC", decimals: 18 },
  { chainId: 56, address: "0x55d398326f99059ff775485246999027b3197955", symbol: "USDT", decimals: 18 },
  { chainId: 4326, address: "0xfafddbb3fc7688494971a79cc65dca3ef82079e7", symbol: "USDm", decimals: 18 },
];

/** Source chains production must never credit from: the MegaETH testnet and the Solana devnet id (review B1). */
export const REFUSED_PRODUCTION_SOURCE_CHAINS: readonly number[] = [6343, 900002];

const KNOWN_CHAINS: readonly DepositChain[] = [
  { chainId: 1, name: "Ethereum", rpcSecret: "DEPOSIT_RPC_ETH", extraDepth: 0, sweepMinMicrousd: 250_000_000, finalitySeconds: 900 },
  { chainId: 8453, name: "Base", rpcSecret: "DEPOSIT_RPC_BASE", extraDepth: 0, sweepMinMicrousd: 10_000_000, finalitySeconds: 1200 },
  { chainId: 56, name: "BNB Smart Chain", rpcSecret: "DEPOSIT_RPC_BSC", extraDepth: 15, sweepMinMicrousd: 10_000_000, finalitySeconds: 60 },
  { chainId: 4326, name: "MegaETH", rpcSecret: "DEPOSIT_RPC_MEGAETH", extraDepth: 0, sweepMinMicrousd: 10_000_000, finalitySeconds: 60 },
];

/** A chain's facts: one of the four, or a test chain (`DEPOSIT_RPC_<chain id>`, no extra depth, a $10 sweep). */
export function depositChain(chainId: number): DepositChain {
  return (
    KNOWN_CHAINS.find((c) => c.chainId === chainId) ?? {
      chainId,
      name: `Chain ${chainId}`,
      rpcSecret: `DEPOSIT_RPC_${chainId}`,
      extraDepth: 0,
      sweepMinMicrousd: 10_000_000,
      finalitySeconds: 60,
    }
  );
}

const TOKEN_ENTRY = /^([1-9][0-9]{0,15}):(0x[0-9a-f]{40}):([0-9]{1,2}):([A-Za-z0-9]{1,16})$/;

/**
 * DEPOSIT_TOKENS: `chainId:token:decimals:SYMBOL`, comma-separated, the address in lower case, e.g.
 * `8453:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913:6:USDC`. Empty: deposits are off. Throws on anything else.
 */
export function parseDepositTokens(text: string): DepositToken[] {
  if (text.trim() === "") return [];
  const tokens: DepositToken[] = [];
  for (const raw of text.split(",")) {
    const item = raw.trim();
    const m = TOKEN_ENTRY.exec(item);
    if (m === null) throw new Error(`${JSON.stringify(item)} is not chainId:0x<40 lower-case hex digits>:decimals:SYMBOL`);
    const chainId = Number(m[1]);
    const decimals = Number(m[3]);
    if (!Number.isSafeInteger(chainId)) throw new Error(`chain id ${m[1]} is not a safe integer`);
    if (decimals < 6 || decimals > 18) throw new Error(`${item}: decimals must be 6 to 18`);
    if (tokens.some((t) => t.chainId === chainId && t.address === m[2])) throw new Error(`${item} is listed twice`);
    if (tokens.some((t) => t.chainId === chainId && t.symbol === m[4])) throw new Error(`${item}: chain ${chainId} lists ${m[4]} twice`);
    tokens.push({ chainId, address: m[2]!, symbol: m[4]!, decimals });
  }
  return tokens;
}

/** The chains DEPOSIT_TOKENS lists, in the order first listed. */
export function depositChains(tokens: readonly DepositToken[]): DepositChain[] {
  return [...new Set(tokens.map((t) => t.chainId))].map(depositChain);
}

/** DEPOSIT_TOKENS's rule on its own: the syntax. */
export function depositTokensProblem(text: string): string | null {
  try {
    parseDepositTokens(text);
    return null;
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
}

/** DEPOSIT_TOKENS in production: only PRODUCTION_DEPOSIT_TOKENS, as listed there, and no refused chain. Null when it holds. */
export function productionDepositTokensProblem(text: string): string | null {
  let tokens: DepositToken[];
  try {
    tokens = parseDepositTokens(text);
  } catch {
    return null; // the row's own check says why
  }
  for (const t of tokens) {
    if (REFUSED_PRODUCTION_SOURCE_CHAINS.includes(t.chainId)) return `lists chain ${t.chainId}, which production never credits deposits from`;
    const known = PRODUCTION_DEPOSIT_TOKENS.find((p) => p.chainId === t.chainId && p.address === t.address);
    if (known === undefined) return `lists ${t.chainId}:${t.address}, which is not a production deposit token`;
    if (known.decimals !== t.decimals || known.symbol !== t.symbol) return `lists ${t.chainId}:${t.address} as ${t.decimals}:${t.symbol}; it is ${known.decimals}:${known.symbol}`;
  }
  return null;
}

const bytes32Problem = (value: string): string | null => (value === "" || /^0x[0-9a-f]{64}$/.test(value) ? null : "is not 0x and 64 lower-case hex digits");
const lowerAddressProblem = (value: string): string | null => (value === "" || /^0x[0-9a-f]{40}$/.test(value) ? null : "is not an EVM address in lower case (0x and 40 hex digits)");

const DEPOSIT_SOURCE = "Track B2 of the stablecoin deposits (contracts/deposit/README.md; the review of the plan, §3).";

/** The rows; index.ts appends them to SETTINGS. */
export function depositSettings(): readonly SettingSpec[] {
  return [
    {
      name: "DEPOSIT_TOKENS",
      key: "depositTokens",
      workers: ["jobs", "console"],
      type: "text",
      default: "",
      textCheck: depositTokensProblem,
      source: `${DEPOSIT_SOURCE} Empty by default: deposits are off until the factory is deployed and the treasury chosen.`,
      doc:
        "The tokens deposits are credited in, `chainId:token:decimals:SYMBOL`, comma-separated (token in lower case). Empty: deposits are off. " +
        "Production takes only the canonical USDC, USDT and USDm of Ethereum, Base, BSC and MegaETH mainnet. Must equal gray-credit-signer's DEPOSIT_TOKENS.",
    },
    {
      name: "DEPOSIT_FACTORY_ADDRESS",
      key: "depositFactoryAddress",
      workers: ["jobs", "console"],
      type: "text",
      default: "",
      textCheck: lowerAddressProblem,
      source: `${DEPOSIT_SOURCE} The factory of contracts/deposit, deployed through the CREATE2 proxy at one address on every chain.`,
      doc: "The DepositFactory, in lower case: the same address on every deposit chain. Must equal gray-credit-signer's DEPOSIT_FACTORY_ADDRESS.",
    },
    {
      name: "DEPOSIT_EVM_CLONE_INIT_HASH",
      key: "depositEvmCloneInitHash",
      workers: ["jobs", "console"],
      type: "text",
      default: "",
      textCheck: bytes32Problem,
      source: `${DEPOSIT_SOURCE} The factory's cloneInitCodeHash(); determined by the factory address (its implementation is its CREATE at nonce 1).`,
      doc: "keccak256 of a deposit clone's init code (DepositFactory.cloneInitCodeHash()), in lower case. A workspace's deposit address is CREATE2 of the factory, the workspace's salt and this.",
    },
    {
      name: "DEPOSIT_SCAN_SECONDS",
      key: "depositScanSeconds",
      workers: ["jobs"],
      type: "int",
      default: "15",
      min: 2,
      max: 600,
      source: `${DEPOSIT_SOURCE} Pending deposits show within a scan; 15 s is a few blocks on Ethereum and stays within a paid RPC plan's log quota.`,
      doc: "How often each deposit chain's watcher scans its deposit addresses (one RoundDO `deposit_<chain id>` per chain).",
    },
    {
      name: "DEPOSIT_LOG_BLOCKS",
      key: "depositLogBlocks",
      workers: ["jobs"],
      type: "int",
      default: "1000",
      min: 1,
      max: 10000,
      source: `${DEPOSIT_SOURCE} Common providers cap eth_getLogs ranges between 1,000 and 10,000 blocks; 1,000 is under every cap.`,
      doc: "The most blocks one eth_getLogs call of the deposit watcher spans.",
    },
    {
      name: "DEPOSIT_ADDRESS_CHUNK",
      key: "depositAddressChunk",
      workers: ["jobs"],
      type: "int",
      default: "150",
      min: 1,
      max: 200,
      source: `${DEPOSIT_SOURCE} Review §2 #20: some providers refuse a topic OR list of 500 addresses; 100 to 200 per call is accepted.`,
      doc: "How many deposit addresses one eth_getLogs call of the deposit watcher names in its `to` topic.",
    },
    {
      name: "DEPOSIT_RPC_TIMEOUT_MS",
      key: "depositRpcTimeoutMs",
      workers: ["jobs"],
      type: "int",
      default: "10000",
      min: 1000,
      max: 60000,
      source: `${DEPOSIT_SOURCE} A getLogs over 150 addresses and 1,000 blocks answers within a few seconds on a paid node.`,
      doc: "How long the deposit watcher and sweeper wait for one JSON-RPC call to a deposit chain.",
    },
    {
      name: "DEPOSIT_SWEEP_SECONDS",
      key: "depositSweepSeconds",
      workers: ["jobs"],
      type: "int",
      default: "300",
      min: 30,
      max: 86400,
      source: `${DEPOSIT_SOURCE} Sweeping is housekeeping: the deposit is credited whether or not it is swept.`,
      doc: "How often each deposit chain's sweeper (RoundDO `deposit_sweep_<chain id>`) looks for deposit addresses to sweep.",
    },
    {
      name: "DEPOSIT_SWEEP_BATCH",
      key: "depositSweepBatch",
      workers: ["jobs"],
      type: "int",
      default: "50",
      min: 1,
      max: 256,
      source: `${DEPOSIT_SOURCE} DepositFactory.MAX_BATCH is 256; 50 sweeps cost about 3.5M gas, well under every chain's block limit.`,
      doc: "The most deposit addresses one sweepBatch transaction sweeps.",
    },
    {
      name: "DEPOSIT_SWEEP_MAX_FEE_GWEI",
      key: "depositSweepMaxFeeGwei",
      workers: ["jobs"],
      type: "int",
      default: "100",
      min: 1,
      max: 10000,
      source: `${DEPOSIT_SOURCE} A sweep can wait: above this fee per gas it is put off to a later pass.`,
      doc: "The most fee per gas, in gwei, a sweep transaction offers; when the chain asks more, the sweep waits.",
    },
    {
      name: "DEPOSIT_SWEEP_STUCK_SECONDS",
      key: "depositSweepStuckSeconds",
      workers: ["jobs"],
      type: "int",
      default: "1800",
      min: 60,
      max: 86400,
      source: `${DEPOSIT_SOURCE} Half an hour is many blocks on every deposit chain.`,
      doc: "How long a sent sweep may go without a receipt before the sweeper sends it again under the same nonce with fees at least 15% higher (at most DEPOSIT_SWEEP_MAX_FEE_GWEI); once the nonce is used by none of them, it gives them up.",
    },
    {
      name: "DEPOSIT_MAX_MICROUSD",
      key: "depositMaxMicrousd",
      workers: ["jobs"],
      type: "int",
      default: String(DEPOSIT_CONTRACT_MAX_MICROUSD),
      min: 1_000_000,
      max: DEPOSIT_CONTRACT_MAX_MICROUSD,
      source:
        `${DEPOSIT_SOURCE} GrayCredit refuses a mint above caps.maxMintAmount ($10,000 as deployed), and a deposit's mint is the whole ` +
        "transfer (launch audit LB-1). The maximum is that cap: raising it needs the contract's cap raised first and this bound changed with it.",
      doc:
        "The largest deposit, in micro-USD, the deposit watcher requests a mint for. A final deposit above it is held (`held_over_cap`, alert " +
        "`deposit_held_over_cap`) for an operator. At most GrayCredit's maxMintAmount: the watcher reads the contract's caps before it " +
        "requests a mint and holds what they would refuse, with the alert `deposit_cap_mismatch` while this is above them.",
    },
  ];
}

/** The rules between the deposit vars; index.ts appends them to TEXT_CROSS_CHECKS. */
export const DEPOSIT_TEXT_CROSS_CHECKS: readonly TextCrossCheck[] = [
  {
    workers: ["jobs", "console"],
    names: ["DEPOSIT_TOKENS", "DEPLOY_ENV"],
    check: (tokens, env) => (env === "production" ? productionDepositTokensProblem(tokens) : null),
    source: "Review §3.2 and B1: production credits only the canonical mainnet tokens, never a test chain's (free) tokens.",
  },
  {
    workers: ["jobs", "console"],
    names: ["DEPOSIT_TOKENS", "DEPOSIT_FACTORY_ADDRESS"],
    check: (tokens, factory) => (tokens.trim() === "" || factory !== "" ? null : "needs DEPOSIT_FACTORY_ADDRESS: deposit addresses are the factory's"),
    source: "A deposit address is CREATE2 of the factory (contracts/deposit/README.md \"Addresses\").",
  },
  {
    workers: ["jobs", "console"],
    names: ["DEPOSIT_EVM_CLONE_INIT_HASH", "DEPOSIT_FACTORY_ADDRESS"],
    check: (hash, factory) => ((hash === "") === (factory === "") ? null : "is set without DEPOSIT_FACTORY_ADDRESS, or missing beside it; set both or neither"),
    source: "A deposit address is CREATE2 of the factory, the salt and the clone init code hash: one without the other names no address.",
  },
];

/** The MegaETH mainnet: where production's GrayCredit must be before real-money deposits are credited. */
export const DEPOSIT_LEDGER_CHAIN_ID = 4326;

/**
 * The owner's rollout rule for production (review B1): deposits of real stablecoins are credited only on a mainnet
 * ledger. With DEPLOY_ENV production and DEPOSIT_TOKENS listing anything, the ledger chain must be 4326: the jobs'
 * CHAIN_ID, the console's CREDIT_CHAIN_ID (empty: MOSS_NETWORK's chain, 4326 for mainnet). gray-credit-signer refuses
 * the same on its own CHAIN_ID. `values` are a worker's parsed settings, by key.
 */
export function depositLedgerProblem(worker: string, values: Readonly<Record<string, unknown>>): { name: string; message: string; names: [string, string] } | null {
  if (values.deployEnv !== "production" || typeof values.depositTokens !== "string" || values.depositTokens.trim() === "") return null;
  if (worker === "jobs") {
    return values.chainId === DEPOSIT_LEDGER_CHAIN_ID
      ? null
      : { name: "DEPOSIT_TOKENS", names: ["DEPOSIT_TOKENS", "CHAIN_ID"], message: `needs CHAIN_ID ${DEPOSIT_LEDGER_CHAIN_ID} in production: deposits are credited only on the mainnet ledger (CHAIN_ID is ${String(values.chainId)})` };
  }
  if (worker === "console") {
    const explicit = typeof values.creditChainId === "string" ? values.creditChainId : "";
    const ledger = explicit !== "" ? explicit : values.mossNetwork === "mainnet" ? String(DEPOSIT_LEDGER_CHAIN_ID) : "6343";
    return ledger === String(DEPOSIT_LEDGER_CHAIN_ID)
      ? null
      : { name: "DEPOSIT_TOKENS", names: ["DEPOSIT_TOKENS", "CREDIT_CHAIN_ID"], message: `needs the credit chain ${DEPOSIT_LEDGER_CHAIN_ID} in production: deposits are credited only on the mainnet ledger (the credit chain is ${ledger})` };
  }
  return null;
}

/** The deposit part of the jobs and console configurations. */
export interface DepositConfig {
  readonly depositTokens: string;
  readonly depositFactoryAddress: string;
  readonly depositEvmCloneInitHash: string;
}

/** The jobs' own deposit settings. */
export interface DepositJobsConfig extends DepositConfig {
  readonly depositScanSeconds: number;
  readonly depositLogBlocks: number;
  readonly depositAddressChunk: number;
  readonly depositRpcTimeoutMs: number;
  readonly depositSweepSeconds: number;
  readonly depositSweepBatch: number;
  readonly depositSweepMaxFeeGwei: number;
  readonly depositSweepStuckSeconds: number;
  readonly depositMaxMicrousd: number;
}

/** Whether deposits are on: tokens listed (the cross checks then require the factory and the hash). */
export function depositsEnabled(config: DepositConfig): boolean {
  return config.depositTokens.trim() !== "" && config.depositFactoryAddress !== "" && config.depositEvmCloneInitHash !== "";
}
