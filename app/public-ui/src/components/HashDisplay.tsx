import { motion } from "framer-motion";
import CopyButton from "./CopyButton";

interface HashDisplayProps {
  hash: string;
}

export default function HashDisplay({ hash }: HashDisplayProps) {
  const groups: string[] = [];
  for (let i = 0; i < hash.length; i += 8) {
    groups.push(hash.slice(i, i + 8));
  }

  return (
    <div className="flex items-center gap-2 flex-wrap">
      <code className="font-mono text-sm tracking-wide text-ink">
        {groups.map((group, gi) => (
          <span key={gi} className="inline-block mr-[0.35em]">
            {group.split("").map((char, ci) => (
              <motion.span
                key={`${gi}-${ci}`}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 0.15, delay: (gi * 8 + ci) * 0.008 }}
              >
                {char}
              </motion.span>
            ))}
          </span>
        ))}
      </code>
      <CopyButton text={hash} />
    </div>
  );
}
