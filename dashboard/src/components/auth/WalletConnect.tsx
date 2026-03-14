"use client";

import type { ReactNode } from "react";
import {
  ConnectButton,
  RainbowKitProvider,
  getDefaultConfig,
} from "@rainbow-me/rainbowkit";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { WagmiProvider } from "wagmi";
import { mainnet, sepolia } from "wagmi/chains";

const projectId =
  process.env.NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID ?? "olympus-civic-demo";

const config = getDefaultConfig({
  appName: "Olympus Civic",
  projectId,
  chains: [mainnet, sepolia],
  ssr: true,
});

const queryClient = new QueryClient();

export function WalletConnectProvider({ children }: { children: ReactNode }) {
  return (
    <WagmiProvider config={config}>
      <QueryClientProvider client={queryClient}>
        <RainbowKitProvider>{children}</RainbowKitProvider>
      </QueryClientProvider>
    </WagmiProvider>
  );
}

export function WalletConnect() {
  const usingDemoProjectId =
    projectId === "olympus-civic-demo" || projectId.trim().length === 0;

  return (
    <div className="space-y-3">
      <ConnectButton
        chainStatus="icon"
        accountStatus="address"
        showBalance={false}
      />
      {usingDemoProjectId && (
        <p
          className="text-xs"
          style={{ color: "var(--color-text-muted)" }}
        >
          Set NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID to enable production
          WalletConnect sessions.
        </p>
      )}
    </div>
  );
}
