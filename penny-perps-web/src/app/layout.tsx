import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
    title: "Penny Perps | The Dark Pool",
    description: "Privacy-preserving meme coin perpetuals.",
};

export default function RootLayout({
    children,
}: Readonly<{
    children: React.ReactNode;
}>) {
    return (
        <html lang="en">
            <body className="antialiased bg-black text-green-500 font-mono">
                {children}
            </body>
        </html>
    );
}
