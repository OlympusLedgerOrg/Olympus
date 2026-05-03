import { useSkin } from "../skins/SkinContext";

interface JsonTabProps {
  jsonInput: string;
  setJsonInput: (v: string) => void;
  jsonError: string | null;
  jsonCanonical: string | null;
  isPending: boolean;
  wasmError?: string | null;
  onSubmit: () => Promise<void>;
  onFormat: () => void;
  onMinify: () => void;
}

export default function JsonTab({
  jsonInput,
  setJsonInput,
  jsonError,
  jsonCanonical,
  isPending,
  wasmError,
  onSubmit,
  onFormat,
  onMinify,
}: JsonTabProps) {
  const { skin } = useSkin();
  return (
    <div>
      {wasmError && (
        <p className="err-text" style={{ marginBottom: "0.75rem" }}>
          ⚠ {wasmError}
        </p>
      )}
      <div className="field-head">
        <label htmlFor="json-input" className="terminal-label">
          JSON document
        </label>
        <span className="status-pill status-neutral">
          {jsonInput.length.toLocaleString()}B
        </span>
      </div>
      <textarea
        id="json-input"
        value={jsonInput}
        onChange={(event) => {
          setJsonInput(event.target.value);
        }}
        rows={7}
        placeholder='{"title":"Budget 2025","amount":1000000}'
        spellCheck={false}
        className={skin.classes.input}
        style={{ resize: "vertical" }}
      />
      <div className="quick-actions">
        <button type="button" className={skin.classes.buttonSecondary} onClick={onFormat}>
          FORMAT
        </button>
        <button type="button" className={skin.classes.buttonSecondary} onClick={onMinify}>
          MINIFY
        </button>
        <button
          type="button"
          className={skin.classes.buttonSecondary}
          onClick={() =>
            setJsonInput(
              JSON.stringify(
                { title: "Budget 2025", amount: 1000000, agency: "demo" },
                null,
                2,
              ),
            )
          }
        >
          SAMPLE
        </button>
      </div>
      {jsonCanonical && (
        <p className="preview-line">
          CANONICAL:{" "}
          {jsonCanonical.length > 160
            ? `${jsonCanonical.slice(0, 160)}...`
            : jsonCanonical}
        </p>
      )}
      {jsonError && <p className="err-text">{jsonError}</p>}
      <button
        type="button"
        className={skin.classes.buttonPrimary}
        onClick={() => void onSubmit()}
        disabled={isPending || !jsonInput.trim()}
        style={{ marginTop: "0.75rem" }}
      >
        {isPending ? "EXECUTING..." : "CANONICALIZE_AND_HASH"}
      </button>
    </div>
  );
}
