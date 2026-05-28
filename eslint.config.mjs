// Repository-root ESLint flat config.
//
// Reason this file exists: CodeRabbit's ESLint integration runs from the
// repository root and looks for `eslint` declared in the root
// `package.json` plus a root-level `eslint.config.js`. Without both,
// it skips the lint check entirely ("ESLint skipped: no ESLint
// configuration detected in root package.json") and surfaces a tool
// warning on every PR.
//
// The real lint surface lives in `app/public-ui/eslint.config.js`
// (React + TypeScript rules invoked via `pnpm --filter app/public-ui
// lint`). That config keeps working unchanged: ESLint flat-config
// resolution starts from the current working directory and walks up,
// so running ESLint from within `app/public-ui/` still picks up the
// nested config first.
//
// To avoid double-linting public-ui files from the root (which would
// apply the wrong rule set — root has no React/JSX plugins), we ignore
// that subtree here. The net effect: CodeRabbit can invoke ESLint at
// the repo root without errors; public-ui keeps its workspace-local
// rules; nothing else in the tree has ESLint coverage today, so the
// root config is intentionally a passthrough.
export default [
  { ignores: ['app/public-ui/**', '**/node_modules/**', '**/dist/**'] },
];
