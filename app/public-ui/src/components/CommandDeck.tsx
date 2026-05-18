import type { Tab } from "../lib/types";
import { useSkin } from "../skins/SkinContext";

type Command = {
  id: Tab;
  code: string;
  title: string;
  description: string;
  hotkey: string;
};

const COMMANDS: Command[] = [
  {
    id: "hash",
    code: "VERIFY",
    title: "Hash or drop a file",
    description:
      "Paste a BLAKE3 hash, or drop a file to hash it locally — then ask the ledger if it's known.",
    hotkey: "01",
  },
  {
    id: "proof",
    code: "PROOF",
    title: "Audit a bundle",
    description: "Submit the full proof object and make the backend prove its receipts.",
    hotkey: "02",
  },
  {
    id: "commit",
    code: "COMMIT",
    title: "Commit to ledger",
    description: "Ingest a document (source or redacted) into the SMT ledger. Requires an API key.",
    hotkey: "03",
  },
];

export default function CommandDeck({
  activeTab,
  onSelect,
  hasApiKey,
}: {
  activeTab: Tab;
  onSelect: (tab: Tab) => void;
  hasApiKey: boolean;
}) {
  const { skin } = useSkin();

  return (
    <section className="command-deck" aria-label="Verification command deck">
      {COMMANDS.map((command) => {
        // 03 COMMIT is only visible to API key holders
        if (command.id === "commit" && !hasApiKey) return null;
        const active = activeTab === command.id;
        return (
          <button
            key={command.id}
            type="button"
            className={`command-card ${active ? "is-active" : ""} ${skin.classes.card}`}
            onClick={() => onSelect(command.id)}
            aria-pressed={active}
          >
            <span className="command-hotkey">{command.hotkey}</span>
            <span className="command-code">{command.code}</span>
            <strong>{command.title}</strong>
            <span>{command.description}</span>
          </button>
        );
      })}
    </section>
  );
}
