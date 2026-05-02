import { EXAMPLE_PROOF } from "../lib/constants";

interface ProofTabProps {
  proofInput: string;
  setProofInput: (v: string) => void;
  proofError: string | null;
  isPending: boolean;
  onSubmit: () => void;
}

export default function ProofTab({
  proofInput,
  setProofInput,
  proofError,
  isPending,
  onSubmit,
}: ProofTabProps) {
  return (
    <div>
      <label htmlFor="proof-input" className="terminal-label">
        Proof bundle JSON
      </label>
      <textarea
        id="proof-input"
        value={proofInput}
        onChange={(event) => {
          setProofInput(event.target.value);
        }}
        rows={9}
        placeholder='{"content_hash":"...","merkle_root":"...","merkle_proof":{}}'
        spellCheck={false}
        className="cyber-input"
        style={{ resize: "vertical" }}
      />
      <div className="quick-actions">
        <button
          type="button"
          className="icon-text-btn"
          onClick={() => setProofInput(JSON.stringify(EXAMPLE_PROOF, null, 2))}
        >
          SAMPLE
        </button>
        <button
          type="button"
          className="icon-text-btn"
          onClick={() => setProofInput("")}
        >
          CLEAR
        </button>
      </div>
      <button
        type="button"
        className="cyber-button"
        onClick={onSubmit}
        disabled={isPending || !proofInput.trim()}
        style={{ marginTop: "0.75rem" }}
      >
        {isPending ? "EXECUTING..." : "EXECUTE_VERIFICATION"}
      </button>
      {proofError && <p className="err-text">{proofError}</p>}
    </div>
  );
}
