#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { hasSpdxLicenseHeader } from "./check-license-headers.mjs";

test("accepts valid SPDX license headers", () => {
  const validHeaders = [
    "// SPDX-FileCopyrightText: 2026 Olympus Contributors\n// SPDX-License-Identifier: Apache-2.0\n",
    "#!/usr/bin/env bash\n# SPDX-License-Identifier: Apache-2.0\n",
    "-- SPDX-License-Identifier: Apache-2.0\nSELECT 1;\n",
    "/*\n * SPDX-FileCopyrightText: 2026 Olympus Contributors\n * SPDX-License-Identifier: Apache-2.0\n */\n",
  ];

  for (const header of validHeaders) {
    assert.equal(hasSpdxLicenseHeader(header), true);
  }
});

test("rejects SPDX text outside a file header comment", () => {
  const source = 'const license = "SPDX-License-Identifier: Apache-2.0";\n';

  assert.equal(hasSpdxLicenseHeader(source), false);
});

test("--update-baseline keeps only reviewed legacy baseline entries", () => {
  const tempRepo = mkdtempSync(path.join(tmpdir(), "olympus-license-headers-"));
  const script = fileURLToPath(new URL("./check-license-headers.mjs", import.meta.url));

  try {
    writeFileSync(path.join(tempRepo, ".license-header-baseline"), "legacy.js\n", "utf8");
    writeFileSync(path.join(tempRepo, "legacy.js"), "console.log('legacy');\n", "utf8");
    writeFileSync(path.join(tempRepo, "new.js"), "console.log('new');\n", "utf8");
    execFileSync("git", ["init"], { cwd: tempRepo, stdio: "ignore" });
    execFileSync("git", ["add", "."], { cwd: tempRepo, stdio: "ignore" });

    const output = execFileSync(process.execPath, [script, "--update-baseline"], {
      cwd: tempRepo,
      encoding: "utf8",
    });
    const baseline = readFileSync(path.join(tempRepo, ".license-header-baseline"), "utf8");

    assert.match(output, /Updated \.license-header-baseline \(1 legacy files\)\./);
    assert.match(baseline, /^legacy\.js$/m);
    assert.doesNotMatch(baseline, /^new\.js$/m);
  } finally {
    rmSync(tempRepo, { recursive: true, force: true });
  }
});
