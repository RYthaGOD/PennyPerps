"use client";
import { GhostPanel } from "@/components/GhostPanel";
import { OrderEntry } from "@/components/OrderEntry";
import { TradingChart } from "@/components/TradingChart";

export default function Home() {
    return (
        <main className="flex min-h-screen flex-col items-center justify-center p-4 bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-zinc-900 via-black to-black">
            <div className="z-10 w-full max-w-7xl font-mono text-sm flex flex-col gap-8">
                <div className="text-center space-y-2 mb-8">
                    <h1 className="text-4xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-green-400 to-emerald-600 animate-pulse">PENNY PERPS</h1>
                    <p className="text-zinc-500 tracking-widest text-xs">OFF-CHAIN DARK POOL SIMULATION</p>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 w-full">
                    {/* Left Column: Chart */}
                    <div className="lg:col-span-8">
                        <TradingChart />
                    </div>

                    {/* Right Column: Order Entry & Ghost Panel */}
                    <div className="lg:col-span-4 space-y-6">
                        <OrderEntry />
                        <GhostPanel />
                    </div>
                </div>

                <div className="text-zinc-800 text-[10px] mt-12 text-center mx-auto max-w-md">
                    WARNING: OPERATING IN SIMULATION MODE. KEYS ARE EPHEMERAL. DO NOT USE REAL FUNDS.
                </div>
            </div>
        </main>
    );
}
