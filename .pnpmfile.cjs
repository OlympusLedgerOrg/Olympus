'use strict'

// Force transitive deps to patched versions.
// - ws: CVE patched in 8.20.1
// - underscore: CVE patched in 1.13.8
// - elliptic: patched version (>=6.6.2) not yet released on npm; suppressed in
//   pnpm.auditConfig.ignoreCves (GHSA-848j-6mx2-7j84, low severity, no fix available)
// - jsonpath (via snarkjs>bfj): no npm-installable fix; build-only code with no
//   user-controlled JSONPath input. Suppressed in pnpm.auditConfig.ignoreCves.

function readPackage (pkg) {
  if (pkg.dependencies?.ws) {
    pkg.dependencies.ws = '^8.20.1'
  }
  if (pkg.devDependencies?.ws) {
    pkg.devDependencies.ws = '^8.20.1'
  }
  if (pkg.dependencies?.underscore) {
    pkg.dependencies.underscore = '^1.13.8'
  }
  if (pkg.devDependencies?.underscore) {
    pkg.devDependencies.underscore = '^1.13.8'
  }

  return pkg
}

module.exports = {
  hooks: {
    readPackage
  }
}
