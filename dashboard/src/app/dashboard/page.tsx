import Link from "next/link";
import { VerificationBadge } from "@/components/auth/VerificationBadge";

export default function DashboardPage() {
  return (
    <main className="flex min-h-screen flex-col items-center px-6 py-12">
      <div className="w-full max-w-3xl space-y-6">
        <header className="space-y-3">
          <h1
            className="text-3xl font-bold tracking-tight"
            style={{ color: "var(--color-primary)", fontFamily: "var(--font-mono)" }}
          >
            Civic Dashboard
          </h1>
          <p style={{ color: "var(--color-text-muted)" }}>
            Verified humans can access Olympus Civic features and submit
            accountability proofs.
          </p>
        </header>

        <VerificationBadge />

        <div
          className="border p-6 text-sm space-y-4"
          style={{
            background: "var(--color-surface)",
            borderColor: "var(--color-border)",
            borderRadius: "var(--radius)",
          }}
        >
          <p>
            You now have access to civic workflows, submission queues, and the
            Olympus verification portal. This area is protected by the
            verification middleware.
          </p>
          <Link
            href="/auth"
            className="inline-flex items-center gap-2 text-sm font-semibold"
            style={{ color: "var(--color-primary)" }}
          >
            Manage verification →
          </Link>
        </div>
      </div>
    </main>
  );
}
