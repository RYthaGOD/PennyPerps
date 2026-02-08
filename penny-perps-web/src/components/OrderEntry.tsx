"use client";
import { useState } from 'react';
import { useDarkMatcher } from '@/hooks/useDarkMatcher';
import { DollarSign, ArrowUpRight, ArrowDownRight, Activity } from 'lucide-react';

export function OrderEntry() {
    const { isConnected, marketData, postIntent, lastFill } = useDarkMatcher();
    const [size, setSize] = useState(100);

    return (
        <div className="border border-green-500/30 bg-black/80 backdrop-blur-md p-6 rounded-lg font-mono text-green-400 w-full max-w-sm shadow-[0_0_20px_rgba(34,197,94,0.1)]">
            <h2 className="text-xl font-bold mb-6 flex items-center gap-2 border-b border-green-500/30 pb-4">
                <Activity className="w-6 h-6 animate-pulse" />
                TERMINAL
            </h2>

            <div className="space-y-6">
                <div className="flex justify-between items-center text-xs uppercase tracking-widest text-green-600">
                    <span>Status</span>
                    <span className={isConnected ? "text-green-400" : "text-red-500"}>
                        {isConnected ? "CONNECTED" : "DISCONNECTED"}
                    </span>
                </div>

                <div className="bg-zinc-900/50 p-4 rounded border border-green-900/50">
                    <div className="text-[10px] text-green-600 uppercase mb-1">Index Price</div>
                    <div className="text-3xl font-bold text-white">
                        ${marketData?.price.toFixed(2) || "---.--"}
                    </div>
                </div>

                <div>
                    <label className="text-[10px] text-green-600 uppercase tracking-widest mb-2 block">Size (USDC)</label>
                    <input
                        type="number"
                        value={size}
                        onChange={(e) => setSize(Number(e.target.value))}
                        className="w-full bg-zinc-900/50 border border-green-900/50 rounded p-3 text-white focus:outline-none focus:border-green-500 transition-colors"
                    />
                </div>

                <div className="grid grid-cols-2 gap-4">
                    <button
                        onClick={() => postIntent('LONG', size)}
                        className="bg-green-600 hover:bg-green-500 text-black py-4 rounded font-bold flex flex-col items-center justify-center gap-1 transition-all active:scale-95"
                    >
                        <ArrowUpRight className="w-6 h-6" />
                        LONG
                    </button>
                    <button
                        onClick={() => postIntent('SHORT', size)}
                        className="bg-red-600 hover:bg-red-500 text-black py-4 rounded font-bold flex flex-col items-center justify-center gap-1 transition-all active:scale-95"
                    >
                        <ArrowDownRight className="w-6 h-6" />
                        SHORT
                    </button>
                </div>

                {lastFill && (
                    <div className="mt-4 bg-green-900/20 border border-green-500/50 p-3 rounded text-xs">
                        <div className="font-bold text-green-400 mb-1">EXECUTION REPORT</div>
                        <div className="flex justify-between">
                            <span>{lastFill.side} {lastFill.ticker}</span>
                            <span>@{lastFill.price}</span>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}
