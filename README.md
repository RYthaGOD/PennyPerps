# Penny Perps: The Dark Pool for Meme Coins

**Penny Perps** is a privacy-first, off-chain derivatives market built for high-volatility assets on Solana. It allows users to trade perpetual futures on long-tail assets (meme coins) with zero gas fees for orders, instant execution, and complete pre-trade anonymity.

![Penny Perps Terminal Concept](https://via.placeholder.com/800x400?text=Penny+Perps+Terminal+Concept)

## 🚀 Vision

Meme coins are the most volatile and exciting asset class in crypto, yet they lack sophisticated trading infrastructure. Existing DEXs are slow, public, and expensive. Penny Perps solves this by introducing a "Dark Pool" model:

-   **Ghost Protocol**: Client-side Zero-Knowledge (ZK) style identity. Your "Ghost Key" signs orders, keeping your main wallet address hidden from the order book.
-   **Dark Matcher**: An off-chain matching engine that executes trades instantly via encrypted WebSocket channels.
-   **Simulation First**: Currently running in **Simulation Mode** using `MockPercolator` engine for risk-free testing.

![Architecture Diagram](https://via.placeholder.com/800x400?text=System+Architecture)

## 🛠️ Technology Stack

-   **Frontend**: Next.js 14, Tailwind CSS, Zustand (State Management).
-   **Cryptography**: `TweetNaCl` (Ed25519 Signing / X25519 Encryption).
-   **Backend**: Node.js WebSocket Server (The "Dark Matcher").
-   **Engine**: `MockPercolator` (TypeScript implementation of Solana VM logic).

## 🎮 How to Run (Simulation)

### Prerequisites
-   Node.js v18+
-   npm / yarn

### 1. Start the Dark Matcher (Backend)
The Matcher acts as the exchange server.
```bash
npx tsx scripts/start-matcher.ts
```

### 2. Start the Ghost Client (Frontend)
The Client is the trading terminal.
```bash
cd penny-perps-web
npm install
npm run dev
```

### 3. Trade
Open [http://localhost:3000](http://localhost:3000).
1.  **Generate Identity**: The app handles this automatically.
2.  **Fund**: Click "Top Up" to receive simulated USDC-P.
3.  **Trade**: Place Long/Short orders on `PEPE-PERP`.

## 📜 Roadmap to Mainnet

-   [x] **Phase 1**: Ghost Key Protocol (Client-Side Privacy).
-   [x] **Phase 2**: Dark Matcher (Off-Chain Execution).
-   [x] **Phase 3**: Terminal UI (TradingView Charts).
-   [ ] **Phase 4**: **Devnet Launch** (LitePercolator Anchor Contract).
-   [ ] **Phase 5**: Mainnet Launch (Real USDC Settlement).

## ⚠️ Disclaimer
This is currently a **Technical Preview / Simulation**. The "Privacy Cash" (USDC-P) has no real value. The keys are stored in your browser's local storage. **Do not use real funds.**

---
*Built with ⚡ by the Penny Perps Team.*
