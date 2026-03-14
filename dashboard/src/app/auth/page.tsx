import { VerificationBadge } from "@/components/auth/VerificationBadge";
import { VerificationWizard } from "@/components/auth/VerificationWizard";

export default function AuthPage() {
  return (
    <main className="flex min-h-screen flex-col items-center px-6 py-12">
      <div className="w-full max-w-3xl space-y-6">
        <header className="space-y-3">
          <h1
            className="text-3xl font-bold tracking-tight"
            style={{ color: "var(--color-primary)", fontFamily: "var(--font-mono)" }}
          >
            Olympus Civic Verification
          </h1>
          <p style={{ color: "var(--color-text-muted)" }}>
            Prove you are a unique human to unlock Olympus Civic features. No
            personal identity is revealed—only cryptographic commitments and a
            location hint at ZIP3 precision.
          </p>
        </header>

        <VerificationBadge compact />

        <div
          className="border p-6"
          style={{
            background: "var(--color-surface)",
            borderColor: "var(--color-border)",
            borderRadius: "var(--radius)",
          }}
        >
          <VerificationWizard />
        </div>
      </div>
    </main>
  );
}
