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
    code: "HASH",
    title: "Verify a digest",
    description: "Paste a BLAKE3 hash and ask the ledger if the artifact is known.",
    hotkey: "01",
  },
  {
    id: "file",
    code: "FILE",
    title: "Drop a file",
    description: "Hash locally in-browser first, then verify or commit when unknown.",
    hotkey: "02",
  },
  {
    id: "json",
    code: "JSON",
    title: "Canon-check JSON",
    description: "Normalize document payloads before lookup so whitespace cannot gaslight you.",
    hotkey: "03",
  },
  {
    id: "proof",
    code: "PROOF",
    title: "Audit a bundle",
    description: "Submit the full proof object and make the backend prove its receipts.",
    hotkey: "04",
  },
];

export default function CommandDeck({
  activeTab,
  onSelect,
}: {
  activeTab: Tab;
  onSelect: (tab: Tab) => void;
}) {
  const { skin } = useSkin();

  return (
    <section className="command-deck" aria-label="Verification command deck">
      {COMMANDS.map((command) => {
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
