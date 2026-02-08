"use client";
import { useEffect, useState } from 'react';
import { useGhostStore } from '@/store/useGhostStore';
import { Copy, RefreshCw, Shield, Wallet, Zap } from 'lucide-react';

export function GhostPanel() {
    const { ghost, balance, init, generateNew, fund } = useGhostStore();
    const [mounted, setMounted] = useState(false);

    useEffect(() => {
        init();
        setMounted(true);
    }, [init]);

    if (!mounted || !ghost) return <div className="animate-pulse text-green-500 font-mono">Initializing Ghost Protocol...</div>;

    return (
        <div className="border border-green-500/30 bg-black/80 backdrop-blur-md p-6 rounded-lg font-mono text-green-400 w-full max-w-md shadow-[0_0_20px_rgba(34,197,94,0.1)]">
            <h2 className="text-xl font-bold mb-6 flex items-center gap-2 border-b border-green-500/30 pb-4">
                <Shield className="w-6 h-6 animate-pulse" />
                GHOST PROTOCOL
            </h2>

            <div className="space-y-6">
                <div className="group">
                    <label className="text-[10px] text-green-600 uppercase tracking-widest mb-1 flex items-center gap-1">
                        <Zap className="w-3 h-3" /> Identity (Signing Key)
                    </label>
                    <div className="text-xs break-all bg-zinc-900/50 p-3 rounded border border-green-900/50 hover:border-green-500/50 transition-colors cursor-pointer flex items-center justify-between">
                        <span className="opacity-70 group-hover:opacity-100 transition-opacity">{ghost.pubKey}</span>
                        <Copy className="w-3 h-3 text-green-700 opacity-0 group-hover:opacity-100" />
                    </div>
                </div>

                <div className="group">
                    <label className="text-[10px] text-green-600 uppercase tracking-widest mb-1 flex items-center gap-1">
                        <Wallet className="w-3 h-3" /> Encryption Key (Rx)
                    </label>
                    <div className="text-xs break-all bg-zinc-900/50 p-3 rounded border border-green-900/50 hover:border-green-500/50 transition-colors">
                        <span className="opacity-70 group-hover:opacity-100 transition-opacity">{ghost.encryptPubKey}</span>
                    </div>
                </div>

                <div className="bg-green-900/10 rounded-lg p-4 border border-green-500/20">
                    <div className="flex justify-between items-end">
                        <div>
                            <label className="text-[10px] text-green-600 uppercase tracking-widest">Privacy Cash Balance</label>
                            <div className="text-3xl font-bold text-white mt-1">
                                ${balance.toLocaleString()}
                                <span className="text-sm text-green-600 font-normal ml-1">USDC-P</span>
                            </div>
                        </div>
                        <button
                            onClick={() => fund(1000)}
                            className="bg-green-600 hover:bg-green-500 text-black px-4 py-2 rounded text-xs font-bold transition-all hover:shadow-[0_0_10px_rgba(34,197,94,0.4)] active:scale-95 flex items-center gap-2"
                        >
                            <Wallet className="w-4 h-4" />
                            TOP UP
                        </button>
                    </div>
                </div>

                <button
                    onClick={generateNew}
                    className="w-full mt-2 border border-red-900/50 text-red-700 hover:text-red-400 hover:bg-red-950/30 hover:border-red-500/50 py-3 rounded text-[10px] uppercase tracking-[0.2em] transition-all flex items-center justify-center gap-2 group"
                >
                    <RefreshCw className="w-3 h-3 group-hover:rotate-180 transition-transform duration-500" />
                    Burn Identity & Regenerate
                </button>
            </div>
        </div>
    );
}
