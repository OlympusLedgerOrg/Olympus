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
    title: "Verify hash or file",
    description:
      "Paste a BLAKE3 hash, or drop a file to hash it locally. Verification sends only the hash.",
    hotkey: "01",
  },
  {
    id: "proof",
    code: "PROOF",
    title: "Audit a bundle",
    description: "Submit the full proof object and make the backend prove its receipts.",
    hotkey: "02",
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
