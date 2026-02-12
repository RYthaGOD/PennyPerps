# Penny Perps: The Ultimate Meme Coin Derivatives Engine

**Penny Perps** is a privacy-first, ultra-fast derivatives market built for high-volatility assets on Solana. It enables permissionless perpetual futures trading on long-tail assets (memecoins) with zero-latency execution and complete pre-trade anonymity.

![Penny Perps Terminal](https://via.placeholder.com/800x400?text=Penny+Perps+Terminal)

## 🚀 Vision: Ultimate Fidelity

Penny Perps has achieved **Ultimate Fidelity**—100% logic and state parity with the audited `percolator` reference implementation. We've moved beyond simulation into a production-ready SBF (Solana Binary Format) system.

- **Ghost Protocol**: Signless, privacy-preserving trading via client-side Ed25519 signature introspection.
- **Pinocchio Shell**: A zero-dependency, lean SBF binary (<75KB) optimized for maximum compute efficiency.
- **Socialization Waterfall**: 100% solvency protection through haircut-based socialization logic.
- **EWMA Risk Smoothing**: Adaptive anti-DoS thresholds that scale with system risk.

## 🛠️ Technology Stack

- **Kernel**: `production.rs` (Ultimate Fidelity SBF Binary).
- **Frontend**: Next.js 14, Tailwind CSS, Zustand.
- **Cryptography**: Ed25519 Signature Introspection (Ghost Protocol).
- **Backend**: Dark Matcher (High-throughput off-chain matching).
- **Oracle**: Chainlink & Pyth Price Feeds (Standardized 32-byte hash interface).

## 🌐 Live on Devnet

Penny Perps is currently operational on Solana Devnet.

| Component | Address |
| --- | --- |
| **Program ID** | `6u8921CKtcMbrR8sfHdc9M6V2NnymqCoKMLURtmivvxE` |
| **Market Slab** | `FZnRiTQZqtJ2rttfZD6T8HvNmAopvjQz9a3xng7t8ihA` |
| **Collateral** | Wrapped SOL (Devnet) |
| **Oracle** | Chainlink SOL/USD |

## 🎮 Getting Started (Local Development)

### 1. Start the Matcher
```bash
npm run matcher
```

### 2. Start the Trading Terminal
```bash
cd penny-perps-web
npm install
npm run dev -- --port 3001
```

### 3. Initialize & Trade
Open `http://localhost:3001` and follow the auto-onboarding flow.

## 📜 Roadmap

- [x] **Phase 1**: Ghost Key Protocol (Client-Side Privacy).
- [x] **Phase 2**: Dark Matcher (Off-Chain Execution).
- [x] **Phase 3**: Ultimate Fidelity Reconstruction (100% Logic Parity).
- [x] **Phase 4**: **Devnet Launch** (Production SBF Binary).
- [/] **Phase 5**: Memecoin Expansion (Permissionless Market Creation).
- [ ] **Phase 6**: Mainnet Alpha.

## 🔍 Research: Memecoin Markets
We are actively researching permissionless market creation for memecoins (BONK, WIF, POPCAT). Check out [MEMECOIN_RESEARCH.md](./MEMECOIN_RESEARCH.md) for the full technical roadmap.

---
*Built with ⚡ by the Penny Perps Team.*
