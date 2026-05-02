interface JsonTabProps {
  jsonInput: string;
  setJsonInput: (v: string) => void;
  jsonError: string | null;
  jsonCanonical: string | null;
  isPending: boolean;
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
  onSubmit,
  onFormat,
  onMinify,
}: JsonTabProps) {
  return (
    <div>
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
        className="cyber-input"
        style={{ resize: "vertical" }}
      />
      <div className="quick-actions">
        <button type="button" className="icon-text-btn" onClick={onFormat}>
          FORMAT
        </button>
        <button type="button" className="icon-text-btn" onClick={onMinify}>
          MINIFY
        </button>
        <button
          type="button"
          className="icon-text-btn"
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
        className="cyber-button"
        onClick={() => void onSubmit()}
        disabled={isPending || !jsonInput.trim()}
        style={{ marginTop: "0.75rem" }}
      >
        {isPending ? "EXECUTING..." : "CANONICALIZE_AND_HASH"}
      </button>
    </div>
  );
}
