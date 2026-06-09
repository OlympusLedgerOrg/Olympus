# Contributing to Olympus

Thanks for your interest in contributing. Before you start:

- **Code of Conduct** — participation is governed by
  [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
- **Governance & decisions** — how changes are reviewed, voted on, and released
  is documented in [`docs/governance.md`](docs/governance.md).
- **Who maintains what / how to become a maintainer** —
  [`MAINTAINERS.md`](MAINTAINERS.md).
- **Proposing substantial changes** — protocol, ZK, threat-model, or governance
  changes go through the [RFC process](docs/rfcs/README.md) (most PRs do not
  need one).
- **Roadmap** — see [`ROADMAP.md`](ROADMAP.md) for direction and where help is
  wanted.
- **Reporting a vulnerability** — do not open a public issue; follow
  [`SECURITY.md`](SECURITY.md).
- **Getting set up** — [`docs/quickstart.md`](docs/quickstart.md) and
  [`docs/development.md`](docs/development.md).

## Licensing and Contributions

All contributions are licensed under Apache 2.0.

### Developer Certificate of Origin (DCO)

Every commit must be signed off under the [Developer Certificate of Origin
1.1](https://developercertificate.org/). The DCO is a lightweight per-commit
attestation — reproduced in full below — by which you certify that you wrote
the patch (or otherwise have the right to submit it under the project's
Apache-2.0 license).

This replaces a separate contributor-license-agreement (CLA) workflow. It is
the same mechanism used by the Linux kernel, Docker, and many other
Apache/MIT-licensed projects.

#### How to sign off a commit

Append a `Signed-off-by` trailer to every commit message:

```text
Signed-off-by: Jane Doe <jane@example.com>
```

The trailer must match the author identity in `git config user.name` /
`user.email`. The easiest way to add it is the `-s` flag:

```bash
git commit -s -m "your message"
```

To sign off every commit on an existing branch you forgot to sign:

```bash
git rebase --signoff main
```

CI verifies the trailer is present on every commit in a pull request and
fails the merge if any commit is missing it.

#### Developer Certificate of Origin 1.1

```text
By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I have the
    right to submit it under the open source license indicated in the file;
    or

(b) The contribution is based upon previous work that, to the best of my
    knowledge, is covered under an appropriate open source license and I
    have the right under that license to submit that work with modifications,
    whether created in whole or in part by me, under the same open source
    license (unless I am permitted to submit under a different license), as
    indicated in the file; or

(c) The contribution was provided directly to me by some other person who
    certified (a), (b) or (c) and I have not modified it.

(d) I understand and agree that this project and the contribution are public
    and that a record of the contribution (including all personal information
    I submit with it, including my sign-off) is maintained indefinitely and
    may be redistributed consistent with this project or the open source
    license(s) involved.
```
