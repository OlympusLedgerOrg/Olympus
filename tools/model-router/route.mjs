#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

const task = process.argv.slice(2).join(" ").trim();
if (!task) {
  console.error('Usage: node tools/model-router/route.mjs "task description"');
  process.exit(1);
}

const lower = task.toLowerCase();
const sensitive =
  /crypto|cryptograph|hash|signature|key material|secret|auth(?:entication|orization)?|permission|scope|proof|zk|snark|smt|migration|security|vulnerab|ledger|redaction/.test(
    lower,
  );
const implementation = /implement|change|fix|refactor|write|patch|debug|test|build|modify/.test(
  lower,
);
const review = /review|audit|threat model|second opinion|independent|check this diff/.test(lower);

function heuristic() {
  if (sensitive)
    return {
      route: "codex",
      reasoning: "high",
      review: "claude",
      basis: "security-sensitive repository rule",
    };
  if (review)
    return {
      route: "claude",
      reasoning: "high",
      review: "codex",
      basis: "independent review request",
    };
  if (implementation)
    return {
      route: "codex",
      reasoning: "medium",
      review: "optional",
      basis: "implementation task",
    };
  return {
    route: "ollama",
    reasoning: "low",
    review: "none",
    basis: "local discovery or explanation",
  };
}

const fallback = heuristic();
const prompt = `Classify this coding task. Return JSON only with keys route, reasoning, review.\nAllowed route: ollama, codex, claude. Allowed reasoning: low, medium, high.\nTask: ${task}`;

try {
  const response = await fetch("http://127.0.0.1:11434/api/chat", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      model: process.env.WISEREPO_OLLAMA_MODEL || "qwen2.5-coder:7b-instruct",
      stream: false,
      format: "json",
      messages: [
        {
          role: "system",
          content:
            "You are a conservative local task router. Never route security-sensitive work to Ollama.",
        },
        { role: "user", content: prompt },
      ],
      options: { temperature: 0, num_predict: 80 },
    }),
    signal: AbortSignal.timeout(4000),
  });
  if (!response.ok) throw new Error(`Ollama HTTP ${response.status}`);
  const body = await response.json();
  const recommendation = JSON.parse(body.message?.content || "{}");
  if (sensitive || !["ollama", "codex", "claude"].includes(recommendation.route))
    throw new Error("unsafe or invalid recommendation");
  // Do not let a local model spend a hosted allowance on routine work.
  if (!sensitive && !implementation && !review) {
    recommendation.route = "ollama";
    recommendation.reasoning = "low";
    recommendation.review = "none";
  }
  // Name the fields explicitly: spreading the model's object would let a reply
  // carrying its own `task` rewrite the reported one.
  console.log(
    JSON.stringify(
      {
        task,
        route: recommendation.route,
        reasoning: recommendation.reasoning,
        review: recommendation.review,
        basis: "Ollama recommendation",
        fallback,
      },
      null,
      2,
    ),
  );
} catch {
  console.log(
    JSON.stringify(
      { task, ...fallback, basis: `${fallback.basis}; Ollama unavailable`, ollama: "unavailable" },
      null,
      2,
    ),
  );
}
