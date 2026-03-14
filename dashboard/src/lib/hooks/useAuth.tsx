"use client";

import type { ReactNode } from "react";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import { useAccount } from "wagmi";
import type { VerificationRecord } from "@/lib/utils/verification";

type VerificationStatus = "loading" | "unverified" | "verified";

type AuthContextValue = {
  walletAddress?: string;
  isConnected: boolean;
  verificationStatus: VerificationStatus;
  verificationRecord: VerificationRecord | null;
  saveVerification: (record: VerificationRecord) => void;
  clearVerification: () => Promise<void>;
};

const STORAGE_KEY = "olympus.verification";

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const { address, isConnected } = useAccount();
  const [verificationRecord, setVerificationRecord] =
    useState<VerificationRecord | null>(null);
  const [verificationStatus, setVerificationStatus] =
    useState<VerificationStatus>("loading");

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (!stored) {
      setVerificationStatus("unverified");
      return;
    }
    try {
      const parsed = JSON.parse(stored) as VerificationRecord;
      setVerificationRecord(parsed);
      setVerificationStatus("verified");
    } catch (error) {
      console.warn("Failed to parse stored verification record", error);
      setVerificationStatus("unverified");
    }
  }, []);

  useEffect(() => {
    if (!isConnected) {
      setVerificationStatus("unverified");
      return;
    }
    if (verificationRecord && address) {
      if (verificationRecord.walletAddress.toLowerCase() !== address.toLowerCase()) {
        setVerificationRecord(null);
        setVerificationStatus("unverified");
        if (typeof window !== "undefined") {
          window.localStorage.removeItem(STORAGE_KEY);
        }
        return;
      }
      setVerificationStatus("verified");
    }
  }, [address, isConnected, verificationRecord]);

  const saveVerification = useCallback((record: VerificationRecord) => {
    setVerificationRecord(record);
    setVerificationStatus("verified");
    if (typeof window !== "undefined") {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(record));
    }
  }, []);

  const clearVerification = useCallback(async () => {
    setVerificationRecord(null);
    setVerificationStatus("unverified");
    if (typeof window !== "undefined") {
      window.localStorage.removeItem(STORAGE_KEY);
    }
    await fetch("/api/auth/verify", { method: "DELETE" });
  }, []);

  const value = useMemo(
    () => ({
      walletAddress: address,
      isConnected,
      verificationStatus,
      verificationRecord,
      saveVerification,
      clearVerification,
    }),
    [address, isConnected, verificationRecord, verificationStatus, saveVerification, clearVerification],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
