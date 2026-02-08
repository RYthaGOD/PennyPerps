"use client";
import { useEffect, useRef, useState } from 'react';
import { useGhostStore } from '@/store/useGhostStore';

import { CONFIG } from '@/lib/config';

export interface MarketUpdate {
    ticker: string;
    price: number;
    vol24h: number;
}

export function useDarkMatcher() {
    const { ghost } = useGhostStore();
    const ws = useRef<WebSocket | null>(null);
    const [isConnected, setIsConnected] = useState(false);
    const [marketData, setMarketData] = useState<MarketUpdate | null>(null);
    const [lastFill, setLastFill] = useState<any>(null);

    useEffect(() => {
        if (!ghost) return;

        const socket = new WebSocket(CONFIG.MATCHER_URL);
        ws.current = socket;

        socket.onopen = () => {
            console.log("Connected to Dark Matcher");
            setIsConnected(true);
            // Authenticate
            socket.send(JSON.stringify({
                type: 'auth',
                pubKey: ghost.pubKey
            }));
        };

        socket.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                if (msg.type === 'market_data') {
                    setMarketData(msg);
                } else if (msg.type === 'fill_report') {
                    setLastFill(msg);
                    console.log("Trade Filled:", msg);
                }
            } catch (e) {
                console.error("WS Parse Error", e);
            }
        };

        socket.onclose = () => setIsConnected(false);

        return () => {
            socket.close();
        };
    }, [ghost]);

    const postIntent = (side: 'LONG' | 'SHORT', size: number) => {
        if (!ws.current || !ghost) return;

        const payload = JSON.stringify({ side, size, timestamp: Date.now() });
        const intentBytes = new TextEncoder().encode(payload);

        const encrypted = ghost.encryptFor(CONFIG.MATCHER_PUBKEY, intentBytes);

        ws.current.send(JSON.stringify({
            type: 'post_intent',
            encrypted
        }));
    };

    return { isConnected, marketData, lastFill, postIntent };
}
