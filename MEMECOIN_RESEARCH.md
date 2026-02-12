# Penny Perps: Memecoin Market Research Report

## 🎯 Executive Summary
Expanding Penny Perps to support memecoin markets (e.g., BONK, WIF, POPCAT) requires a shift from static hardcoded markets to a permissionless initialization model. The current "Ultimate Fidelity" architecture is already designed for this flexibility, but requires standardized templates for high-volatility assets.

---

## 🔮 Oracle Strategy: The "Lindy" Tiering
Memecoins vary wildly in data availability. A robust system should use a tiered oracle approach:

| Tier | Example | Oracle Provider | Feed ID (Devnet) |
|---|---|---|---|
| **Blue Chip Meme** | BONK, WIF | **Pyth (Stable)** | `72b02...` (BONK), `d8299...` (WIF) |
| **Rising Star** | POPCAT, MEW | **Switchboard On-Demand** | Bespoke feeds via Switchboard SDK |
| **New Launch** | Pump.fun graduates | **vAMM Fallback** | Internal price discovery until oracle exists |

### 🛠️ Technical Requirement: Generic Oracle Interface
The program should support both Pyth (v2 accumulator) and Chainlink (legacy) interfaces. Currently, the `index_feed_id` is a 32-byte hash. We can use a tag in the initialization to specify the oracle type.

---

## ⚖️ Risk Management: "Meme-Bps" Calibration
Memecoins can drop 50% in minutes. The current 5% (500 bps) maintenance margin for SOL is insufficient for memecoins.

### Proposed Tiers
- **Standard (SOL/ETH)**: 5% Maint / 10% Initial
- **Volatile (BONK/WIF)**: 15% Maint / 25% Initial
- **Hyper-Volatile (New)**: 30% Maint / 50% Initial (max 2x leverage)

---

## 🏗️ Permissionless Initialization Flow
Currently, initializing a market requires manual script execution. To support "memecoin market creation," we need:

1. **Slab Allocation**: A self-service PDA-based slab creation (or user-provided slab).
2. **Metadata Fetching**: Automatically fetch SPL metadata (name, symbol, decimals) via Metaplex for the UI.
3. **Template-Based `InitMarket`**:
   ```typescript
   // Example Marketplace CLI/UI Action
   deployMemeMarket({
     mint: "DezXAZ... (BONK)",
     oracle: "Pyth",
     collateral: "USDC",
     riskLevel: "Volatile" 
   });
   ```

---

## 🔍 Prior Art & GitHub Research
- **Percolator (Anatoly/Yakovenko)**: The current sharded slab architecture is the "Gold Standard" for performance.
- **Solana Perpetuals (Archived)**: Provides the best reference for "Price Feed Signatures" and permissionless updates.
- **Drift Protocol**: Uses an "Insurance Fund" backstop for permissionless markets.

---

## 🚀 Recommended Roadmap
1. [ ] **Implement Oracle Switching**: Support both Pyth and Proxy price inputs in `production.rs`.
2. [ ] **Meme-Calibration Scripts**: Add templates to `deploy-production-market.ts` for different risk profiles.
3. [ ] **UI Marketplace**: A dashboard tab showing all initialized slabs.
4. [ ] **Automation**: A "Crank" service that auto-detects Pump.fun graduations and initializes markets.

---
**Status**: Research Phase Complete. Ready for implementation planning upon approval.
