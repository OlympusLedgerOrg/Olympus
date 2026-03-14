"use client";

import Link from "next/link";
import { useAuth } from "@/lib/hooks/useAuth";
import {
  VERIFICATION_METHOD_LABELS,
  formatWalletAddress,
} from "@/lib/utils/verification";

type VerificationBadgeProps = {
  compact?: boolean;
};

export function VerificationBadge({ compact = false }: VerificationBadgeProps) {
  const { verificationRecord, verificationStatus, isConnected } = useAuth();

  if (verificationStatus === "loading") {
    return (
      <div
        className="border px-4 py-3 text-sm"
        style={{
          background: "var(--color-surface-muted)",
          borderColor: "var(--color-border)",
          borderRadius: "var(--radius)",
          color: "var(--color-text-muted)",
        }}
      >
        Loading verification status…
      </div>
    );
  }

  if (verificationStatus !== "verified" || !verificationRecord) {
    return (
      <div
        className="border px-4 py-3 text-sm space-y-2"
        style={{
          background: "var(--color-surface-muted)",
          borderColor: "var(--color-border)",
          borderRadius: "var(--radius)",
          color: "var(--color-text-muted)",
        }}
      >
        <p>
          {isConnected
            ? "Wallet connected, verification pending."
            : "Connect a wallet to begin verification."}
        </p>
        <Link
          href="/auth"
          className="inline-flex items-center gap-2 text-xs font-semibold"
          style={{ color: "var(--color-primary)" }}
        >
          Start verification →
        </Link>
      </div>
    );
  }

  return (
    <div
      className="border px-4 py-3 text-sm space-y-2"
      style={{
        background: "var(--color-surface)",
        borderColor: "var(--color-border)",
        borderRadius: "var(--radius)",
      }}
    >
      <div className="flex items-center justify-between">
        <span
          className="text-xs uppercase tracking-[0.2em]"
          style={{ color: "var(--color-text-muted)" }}
        >
          Verified Human
        </span>
        <span
          className="text-xs"
          style={{ color: "var(--color-ok)" }}
        >
          SBT Minted
        </span>
      </div>
      <div className="text-base font-semibold">
        {VERIFICATION_METHOD_LABELS[verificationRecord.method]}
      </div>
      {!compact && (
        <div className="space-y-1 text-xs" style={{ color: "var(--color-text-muted)" }}>
          <p>Wallet: {formatWalletAddress(verificationRecord.walletAddress)}</p>
          <p>Location: {verificationRecord.location.display}</p>
          <p>SBT Token ID: {verificationRecord.sbt.tokenId}</p>
          <p>Issued: {new Date(verificationRecord.issuedAt).toLocaleString()}</p>
        </div>
      )}
    </div>
  );
}
