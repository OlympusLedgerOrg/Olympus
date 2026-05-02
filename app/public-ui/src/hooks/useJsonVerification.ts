import { useCallback, useState } from "react";
import { canonicalJsonEncode, type CanonicalJsonValue } from "../lib/crypto";
import { hashBytes } from "../lib/blake3";
import type { VerdictState } from "../lib/types";

export function useJsonVerification(
  setVerdictResult: (r: VerdictState | null) => void,
  submitHash: (hash: string) => void,
) {
  const [jsonInput, setJsonInput] = useState("");
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [jsonCanonical, setJsonCanonical] = useState<string | null>(null);

  const submitJsonDoc = useCallback(async () => {
    setJsonError(null);
    setJsonCanonical(null);
    setVerdictResult(null);
    try {
      const parsed = JSON.parse(jsonInput) as CanonicalJsonValue;
      const canon = canonicalJsonEncode(parsed);
      const hex = await hashBytes(new TextEncoder().encode(canon));
      setJsonCanonical(canon);
      submitHash(hex);
    } catch (err) {
      setJsonError(err instanceof Error ? err.message : String(err));
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jsonInput, submitHash]);

  const formatJson = useCallback(() => {
    try {
      setJsonInput(JSON.stringify(JSON.parse(jsonInput) as CanonicalJsonValue, null, 2));
      setJsonError(null);
    } catch (err) {
      setJsonError(err instanceof Error ? err.message : String(err));
    }
  }, [jsonInput]);

  const minifyJson = useCallback(() => {
    try {
      setJsonInput(JSON.stringify(JSON.parse(jsonInput) as CanonicalJsonValue));
      setJsonError(null);
    } catch (err) {
      setJsonError(err instanceof Error ? err.message : String(err));
    }
  }, [jsonInput]);

  const reset = useCallback(() => {
    setJsonInput("");
    setJsonError(null);
    setJsonCanonical(null);
  }, []);

  return {
    jsonInput,
    setJsonInput,
    jsonError,
    setJsonError,
    jsonCanonical,
    submitJsonDoc,
    formatJson,
    minifyJson,
    reset,
  };
}
