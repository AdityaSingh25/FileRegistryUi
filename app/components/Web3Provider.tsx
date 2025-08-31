"use client";
import { ReactNode } from "react";
import { WagmiProvider, createConfig, http } from "wagmi";
import { mainnet, polygon, avalanche, sepolia, localhost } from "wagmi/chains";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  ConnectKitProvider,
  ConnectKitButton,
  getDefaultConfig,
} from "connectkit";

// Create config and queryClient outside component to prevent re-initialization
const config = createConfig(
  getDefaultConfig({
    chains: [sepolia],
    transports: {
      [sepolia.id]: http("https://1rpc.io/sepolia"),
    },

    walletConnectProjectId: process.env.NEXT_PUBLIC_PROJECT_ID as string,

    appName: "File Transfer using Blockchain",
    appDescription: "Upload files to IPFS and register on blockchain",
    appUrl: "http://localhost:3000",
  })
);

// Create QueryClient with stable configuration
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60 * 5, // 5 minutes
    },
  },
});

export const Web3Provider = ({ children }: { children: ReactNode }) => {
  return (
    <WagmiProvider config={config}>
      <QueryClientProvider client={queryClient}>
        <ConnectKitProvider>
          <ConnectKitButton />
          {children}
        </ConnectKitProvider>
      </QueryClientProvider>
    </WagmiProvider>
  );
};
