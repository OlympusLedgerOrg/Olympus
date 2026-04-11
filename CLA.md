# Olympus Individual Contributor License Agreement (ICLA)

> **Draft — modeled on the Apache ICLA v2.0.**
> This document must be reviewed by qualified legal counsel before it is
> finalized and adopted by OlympusLedgerOrg.

Version: 1.0-draft  
Project: Olympus (OlympusLedgerOrg/Olympus)

---

Thank you for your interest in contributing to the Olympus open-source
project ("Project"), maintained by OlympusLedgerOrg ("Organization").

This Individual Contributor License Agreement ("Agreement") clarifies the
intellectual property terms under which You submit Contributions to the
Project. Please read it carefully before signing.

---

## 1. Definitions

**"You"** (or **"Your"**) means the individual who signs this Agreement.

**"Contribution"** means any original work of authorship, including any
modifications or additions to an existing work, that You intentionally
submit to the Project for inclusion in, or documentation of, any of the
products owned or managed by the Organization. For the purposes of this
definition, "submit" means any form of electronic, verbal, or written
communication sent to the Organization or its representatives, including
but not limited to communication via issue trackers, source-code control
systems, and mailing lists that are managed by, or on behalf of, the
Organization for the purpose of discussing and improving the Project. A
Contribution does not include any communication that is conspicuously
marked or otherwise designated in writing by You as "Not a Contribution."

**"Cryptographic Component"** means any Contribution that modifies or adds
files under the following paths in the Project repository:

- `protocol/`
- `proofs/circuits/`
- `src/`
- `services/cdhs-smf-rust/src/`
- `verifiers/rust/src/`
- `verifiers/go/`

---

## 2. Grant of Copyright License

Subject to the terms and conditions of this Agreement, You hereby grant to
the Organization and to recipients of software distributed by the
Organization a **perpetual, worldwide, non-exclusive, no-charge,
royalty-free, irrevocable** copyright license to:

- reproduce, prepare derivative works of, publicly display, publicly
  perform, sublicense, and distribute Your Contributions and such
  derivative works in source or object form; and
- sublicense the foregoing rights to third parties, including under
  proprietary or commercial licenses, for the purposes of commercial
  hosting, managed services, or enterprise deployments built on the
  Olympus Protocol.

You retain ownership of the copyright in Your Contributions; this
Agreement is a license grant, not an assignment of ownership.

---

## 3. Grant of Patent License

Subject to the terms and conditions of this Agreement, You hereby grant to
the Organization and to recipients of software distributed by the
Organization a **perpetual, worldwide, non-exclusive, no-charge,
royalty-free, irrevocable** (except as stated in this section) patent
license to make, have made, use, offer to sell, sell, import, and
otherwise transfer Your Contributions, where such license applies only to
those patent claims licensable by You that are necessarily infringed by
Your Contribution(s) alone or by combination of Your Contribution(s) with
the Project to which such Contribution(s) was submitted.

If any entity institutes patent litigation against You or any other entity
(including a cross-claim or counterclaim in a lawsuit) alleging that Your
Contribution, or the Project to which You have contributed, constitutes
direct or contributory patent infringement, then any patent licenses
granted to that entity under this Agreement for that Contribution shall
terminate as of the date such litigation is filed.

---

## 4. Representations

You represent that:

1. You are legally entitled to grant the above licenses. If Your employer
   has rights to intellectual property that You create that includes Your
   Contributions, You represent that You have received permission to make
   Contributions on behalf of that employer, that Your employer has waived
   such rights for Your Contributions to the Project, or that Your employer
   has executed a separate Corporate Contributor License Agreement with the
   Organization.

2. Each of Your Contributions is Your original creation (see Section 7 for
   submissions on behalf of others).

3. Your Contribution submissions include complete details of any
   third-party license or other restriction (including, but not limited to,
   related patents and trademarks) of which You are personally aware and
   which are associated with any part of Your Contributions.

---

## 5. Cryptographic Integrity

For any Contribution that qualifies as a Cryptographic Component, You
additionally represent that, to the best of Your knowledge:

1. **No intentional backdoors.** Your Contribution does not intentionally
   introduce trapdoors, backdoors, or any mechanism designed to allow
   unauthorized access to data protected by the Olympus Protocol.

2. **No weakened entropy or broken primitives.** Your Contribution does not
   intentionally weaken random-number generation, substitute approved
   cryptographic primitives with insecure alternatives, or degrade the
   collision resistance or binding properties of any hash function,
   commitment scheme, or zero-knowledge circuit.

3. **No side-channel vulnerabilities introduced intentionally.** Your
   Contribution does not intentionally introduce timing, power, or
   cache-based side-channel leakage into cryptographic hot paths (e.g.,
   the CD-HS-ST Sparse Merkle Tree implementation, BLAKE3 hashing, or
   Ed25519 signing routines).

4. **Signed commits required.** Contributions to Cryptographic Components
   must be submitted as Git commits bearing a valid GPG or SSH signature
   that can be verified against a key publicly associated with Your GitHub
   account. Pull requests containing unsigned commits that touch
   Cryptographic Component paths will not be merged.

5. **Groth16 trusted-setup ceremony.** If You participate in a Groth16
   multi-party computation (MPC) ceremony for the Olympus ZK circuits, You
   represent that You have destroyed Your randomness contribution ("toxic
   waste") immediately after producing Your ceremony output, and that You
   have not retained, copied, or transmitted that randomness to any third
   party.

---

## 6. Support

You are not expected to provide support for Your Contributions, except to
the extent You desire to provide support. You may provide support for free,
for a fee, or not at all. Unless required by applicable law or agreed to in
writing, You provide Your Contributions on an **"AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND**, either express or implied,
including, without limitation, any warranties or conditions of title,
non-infringement, merchantability, or fitness for a particular purpose.

---

## 7. Contributions on Behalf of Third Parties

Should You wish to submit work that is not Your original creation, You may
submit it to the Organization separately from any Contribution, identifying
the complete details of its source and of any license or other restriction
(including, but not limited to, related patents, trademarks, and license
agreements) of which You are personally aware, and conspicuously marking
the work as "Submitted on behalf of a third-party: [named here]."

---

## 8. Irrevocability

You agree that the licenses granted in Sections 2 and 3 are irrevocable
once a Contribution has been incorporated into any version of the Project
that has been publicly released or distributed. Termination of this
Agreement does not retroactively revoke any license grant for Contributions
already submitted and accepted before the date of termination.

---

## 9. Notification of Changes

You agree to notify the Organization promptly if any of the representations
in Sections 4 or 5 become inaccurate in any respect after the date of
signing.

---

## 10. Governing Law

This Agreement shall be governed by and construed in accordance with the
laws of the jurisdiction in which the Organization is domiciled, without
regard to its conflict of law provisions.

---

## How to Sign

To sign this CLA, post the following comment on the pull request that
triggers the CLA check:

> I have read the CLA Document and I hereby sign the CLA

The `cla-assistant` bot will record your signature in
`.github/cla-signatures.json` and mark the CLA check as passed.

---

*This document is a draft modeled on the Apache ICLA v2.0 and has not been
reviewed by legal counsel. It should not be treated as legal advice.
OlympusLedgerOrg should consult qualified legal counsel before adopting
this agreement for the Olympus project.*
