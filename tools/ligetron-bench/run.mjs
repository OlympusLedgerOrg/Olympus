// SPDX-License-Identifier: Apache-2.0

import { mkdtempSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join, resolve } from "node:path";

const [outputDir, ...selected] = process.argv.slice(2);
if (!outputDir) throw new Error("Usage: node run.mjs OUTPUT_DIR [fixture ...]");
const dir = resolve(outputDir);
const build = process.env.LIGETRON_BUILD;
if (!build) throw new Error("Set LIGETRON_BUILD to the native Windows SDK directory");
const packing = Number(process.env.LIGETRON_PACKING ?? 4096);
const fixtures = JSON.parse(readFileSync(join(dir, "fixtures.json"), "utf8"));
const cases = selected.length ? selected : Object.keys(fixtures);
for (const name of cases) {
  if (!(name in fixtures)) throw new Error("Unknown fixture: " + name);
}
const out = mkdtempSync(join(dir, "benchmark-"));
console.log(out);
const env = { ...process.env, LIGERO_WGPU_BACKEND: "vulkan", LIGERO_REQUIRE_GPU: "1" };

function invoke(tool, cwd, config, label = tool) {
  const start = performance.now();
  const result = spawnSync(resolve(build, tool + ".exe"), [JSON.stringify(config)], {
    cwd,
    env,
    encoding: "utf8",
    timeout: 300_000,
    maxBuffer: 32 * 1024 * 1024,
  });
  const ms = Math.round(performance.now() - start);
  const log = (result.stdout ?? "") + (result.stderr ?? "");
  writeFileSync(join(cwd, label + ".log"), log);
  if (result.error) throw result.error;
  return { status: result.status, log, ms };
}

// The process's "Selected adapter" line, only if it names both the Vulkan
// backend and hardware acceleration. A software or non-Vulkan run is rejected.
function hardwareVulkan(log) {
  const line = log.match(/Selected adapter:.*/)?.[0];
  return line && /acceleration=HARDWARE/.test(line) && /vulkan/i.test(line) ? line : undefined;
}

const rows = [];
for (const name of cases) {
  const args = fixtures[name];
  const cwd = join(out, name);
  mkdirSync(cwd);
  const config = {
    program: join(dir, "relation.wasm"),
    "shader-path": resolve(build, "shader"),
    packing,
    "private-indices": [6, 7, 8, 9],
    args,
  };
  writeFileSync(join(cwd, "config.json"), JSON.stringify(config, null, 2));
  const prover = invoke("webgpu_prover", cwd, config);
  const adapter = hardwareVulkan(prover.log);
  if (prover.status !== 0 || !/Final prove result:\s+true/.test(prover.log) || !adapter) {
    throw new Error(name + ": proving failed on hardware Vulkan\n" + prover.log.slice(-3000));
  }
  const hidden = args.map((arg, index) =>
    index < 5 ? arg : { hex: "00".repeat(arg.hex.length / 2) },
  );
  const verifier = invoke("webgpu_verifier", cwd, { ...config, args: hidden });
  const verifierAdapter = hardwareVulkan(verifier.log);
  if (
    verifier.status !== 0 ||
    !/Final Verify Result:\s+true/.test(verifier.log) ||
    !verifierAdapter
  ) {
    throw new Error(
      name + ": verification failed on hardware Vulkan\n" + verifier.log.slice(-3000),
    );
  }
  const row = {
    name,
    packing,
    bytes: statSync(join(cwd, "proof_data.gz")).size,
    prover_ms: prover.ms,
    verifier_ms: verifier.ms,
    adapter,
    verifier_adapter: verifierAdapter,
  };
  if (name === "membership-50") {
    const changed = structuredClone(hidden);
    const key = Buffer.from(changed[2].hex, "hex");
    key[31] ^= 1;
    changed[2].hex = key.toString("hex");
    const negative = invoke(
      "webgpu_verifier",
      cwd,
      { ...config, args: changed },
      "wrong-query-verifier",
    );
    if (negative.status === 0 || !/Final Verify Result:\s+false/.test(negative.log)) {
      throw new Error(name + ": changed query was not rejected\n" + negative.log.slice(-3000));
    }
    row.wrong_query_rejected = true;
  }
  rows.push(row);
  writeFileSync(join(out, "results.json"), JSON.stringify(rows, null, 2) + "\n");
  console.log(JSON.stringify(row));
}
