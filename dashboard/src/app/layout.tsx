import type { Metadata } from "next";
import localFont from "next/font/local";
import "./globals.css";
import { LayoutShell } from "@/components/layout/LayoutShell";

const geistSans = localFont({
  src: "./fonts/GeistVF.woff",
  variable: "--font-geist-sans",
  weight: "100 900",
});

const geistMono = localFont({
  src: "./fonts/GeistMonoVF.woff",
  variable: "--font-geist-mono",
  weight: "100 900",
});

export const metadata: Metadata = {
  title: "Olympus Dashboard",
  description: "Append-only public ledger dashboard for Olympus",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" data-theme="fight-club" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased min-h-screen`}
      >
        <LayoutShell>{children}</LayoutShell>
      </body>
    </html>
  );
}
