import { create } from 'zustand';
import { GhostKeyRing } from '@/lib/ghost-sdk';

interface GhostState {
    ghost: GhostKeyRing | null;
    balance: number;
    init: () => void;
    generateNew: () => void;
    fund: (amount: number) => void;
}

export const useGhostStore = create<GhostState>((set, get) => ({
    ghost: null,
    balance: 0,
    init: () => {
        if (typeof window !== 'undefined') {
            const ghost = new GhostKeyRing();
            // Load balance from storage or default (Mock)
            const storedBal = localStorage.getItem('GHOST_BALANCE');
            set({ ghost, balance: storedBal ? parseFloat(storedBal) : 0 });
        }
    },
    generateNew: () => {
        const { ghost } = get();
        ghost?.burn();
        localStorage.removeItem('GHOST_BALANCE');
        set({ ghost: new GhostKeyRing(), balance: 0 });
    },
    fund: (amount) => {
        set((state) => {
            const newBal = state.balance + amount;
            localStorage.setItem('GHOST_BALANCE', newBal.toString());
            return { balance: newBal };
        });
    },
}));
