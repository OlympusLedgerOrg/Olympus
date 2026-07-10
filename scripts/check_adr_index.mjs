#!/usr/bin/env node
/**
 * Keep docs/adr/README.md honest.
 *
 * ADRs are part of Olympus's security contract: stale status rows can send a
 * future protocol change down a retired path. This checker verifies that every
 * committed ADR file is present in the index, every indexed ADR has a file, and
 * the status cell matches the ADR's own Status line closely enough to catch
 * obvious drift.
 */
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";

const repo = process.cwd();
const adrDir = path.join(repo, "docs", "adr");
const readmePath = path.join(adrDir, "README.md");

const fileNumber = (name) => {
  const match = /^(?:ADR-)?(\d{4})-.*\.md$/.exec(name);
  return match?.[1] ?? null;
};

const normalizeStatus = (status) =>
  status
    .toLowerCase()
    .replace(/\*\*/g, "")
    .replace(/`/g, "")
    .replace(/\([^)]*\)/g, "")
    .replace(/\s+[—–-]\s+(?:\d{4}-\d{2}-\d{2}|see\b).*$/i, "")
    .replace(/[-,.;:]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();

const statusLine = (file) => {
  const text = readFileSync(path.join(adrDir, file), "utf8");
  const lines = text.split(/\r?\n/).slice(0, 12);
  const statusIndex = lines.findIndex((candidate) => /\bStatus\b/i.test(candidate));
  const line = lines[statusIndex];
  if (!line) {
    return null;
  }
  if (/^#+\s*Status\s*$/i.test(line.trim())) {
    return lines
      .slice(statusIndex + 1)
      .map((candidate) => candidate.trim())
      .find((candidate) => candidate.length > 0) ?? null;
  }
  const tableMatch = /^\|\s*Status\s*\|\s*([^|]+?)\s*\|/.exec(line);
  if (tableMatch) {
    return tableMatch[1].trim();
  }
  return line
    .replace(/^[-*]\s*/, "")
    .replace(/\*\*/g, "")
    .replace(/^\*+/, "")
    .replace(/^Status:\s*/i, "")
    .replace(/^Status\s*[:\-]\s*/i, "")
    .trim();
};

const adrFiles = new Map(
  readdirSync(adrDir)
    .filter((file) => file !== "README.md")
    .map((file) => [fileNumber(file), file])
    .filter(([number]) => number !== null),
);

const readme = readFileSync(readmePath, "utf8");
const rows = [
  ...readme.matchAll(/^\|\s*\[ADR-(\d{4})\]\(([^)]+)\)\s*\|\s*([^|]+)\|\s*([^|]+)\|/gm),
].map((match) => ({
  number: match[1],
  href: match[2].trim(),
  title: match[3].trim(),
  status: match[4].trim(),
}));

const indexed = new Map(rows.map((row) => [row.number, row]));
const errors = [];

for (const [number, file] of adrFiles) {
  const row = indexed.get(number);
  if (!row) {
    errors.push(`ADR-${number} (${file}) is missing from docs/adr/README.md`);
    continue;
  }
  if (row.href !== file) {
    errors.push(`ADR-${number} links to ${row.href}, expected ${file}`);
  }
  const fileStatus = statusLine(file);
  if (!fileStatus) {
    errors.push(`ADR-${number} (${file}) has no Status line near the top`);
    continue;
  }
  const indexedStatus = normalizeStatus(row.status);
  const declaredStatus = normalizeStatus(fileStatus);
  if (indexedStatus !== declaredStatus) {
    errors.push(
      `ADR-${number} status drift: README="${row.status}" but file="${fileStatus}"`,
    );
  }
}

for (const row of rows) {
  if (!adrFiles.has(row.number)) {
    errors.push(`docs/adr/README.md indexes ADR-${row.number}, but ${row.href} is not present`);
  }
}

const sorted = rows.map((row) => row.number);
const resorted = [...sorted].sort();
if (sorted.join(",") !== resorted.join(",")) {
  errors.push("docs/adr/README.md ADR rows are not sorted by number");
}

if (errors.length > 0) {
  console.error("ADR index check failed:");
  for (const error of errors) {
    console.error(`  - ${error}`);
  }
  process.exit(1);
}

console.log(`ADR index check passed (${adrFiles.size} ADRs indexed).`);
