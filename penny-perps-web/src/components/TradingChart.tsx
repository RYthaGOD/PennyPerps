"use client";
import { createChart, ColorType, AreaSeries, Time } from 'lightweight-charts';
import React, { useEffect, useRef } from 'react';
import { useDarkMatcher } from '@/hooks/useDarkMatcher';

export function TradingChart() {
    const chartContainerRef = useRef<HTMLDivElement>(null);
    const { marketData } = useDarkMatcher();
    const seriesRef = useRef<any>(null);

    useEffect(() => {
        if (!chartContainerRef.current) return;

        const chart = createChart(chartContainerRef.current, {
            layout: {
                background: { type: ColorType.Solid, color: 'transparent' },
                textColor: '#4ade80',
            },
            grid: {
                vertLines: { color: 'rgba(34, 197, 94, 0.1)' },
                horzLines: { color: 'rgba(34, 197, 94, 0.1)' },
            },
            width: chartContainerRef.current.clientWidth,
            height: 400,
        });

        chart.timeScale().fitContent();

        const newSeries = chart.addSeries(AreaSeries, {
            lineColor: '#22c55e',
            topColor: 'rgba(34, 197, 94, 0.5)',
            bottomColor: 'rgba(34, 197, 94, 0.0)',
        });

        seriesRef.current = newSeries;

        // Mock Initial Data
        const data: { time: Time; value: number }[] = [];
        let price = 150.0;
        const now = Math.floor(Date.now() / 1000);
        for (let i = 0; i < 100; i++) {
            price += (Math.random() - 0.5);
            data.push({ time: (now - (100 - i) * 60) as Time, value: price });
        }
        // distinct and sorted
        data.sort((a, b) => (a.time as number) - (b.time as number));
        newSeries.setData(data);

        const handleResize = () => {
            chart.applyOptions({ width: chartContainerRef.current!.clientWidth });
        };

        window.addEventListener('resize', handleResize);

        return () => {
            window.removeEventListener('resize', handleResize);
            chart.remove();
        };
    }, []);

    useEffect(() => {
        if (seriesRef.current && marketData) {
            seriesRef.current.update({
                time: Math.floor(Date.now() / 1000) as Time,
                value: marketData.price
            });
        }
    }, [marketData]);

    return (
        <div className="w-full h-[400px] border border-green-500/30 bg-black/80 backdrop-blur-md rounded-lg p-4 shadow-[0_0_20px_rgba(34,197,94,0.1)]">
            <div ref={chartContainerRef} className="w-full h-full" />
        </div>
    );
}
