------------------------------ MODULE OlympusAppendOnly ------------------------------
EXTENDS Sequences, TLC

\* Finite domains so the model can be explored exhaustively by TLC.
DocIds == {"docA", "docB"}
Roots == {"rootA", "rootB"}
RevealSets == {{}, {"section1"}, {"section2"}, {"section1", "section2"}}
Uncommitted == "UNCOMMITTED"

ProofUniverse == [doc: DocIds, root: Roots, revealed: RevealSets]

VARIABLES committed, ledger, proofs, lastCommitted, lastLedger

vars == <<committed, ledger, proofs, lastCommitted, lastLedger>>

IsPrefix(prefix, seq) ==
    /\ Len(prefix) <= Len(seq)
    /\ \A i \in 1..Len(prefix): prefix[i] = seq[i]

Init ==
    /\ committed = [d \in DocIds |-> Uncommitted]
    /\ ledger = <<>>
    /\ proofs = {}
    /\ lastCommitted = committed
    /\ lastLedger = ledger

Commit(doc, root) ==
    /\ doc \in DocIds
    /\ root \in Roots
    /\ committed[doc] = Uncommitted
    /\ committed' = [committed EXCEPT ![doc] = root]
    /\ ledger' = Append(
        ledger,
        [kind |-> "commit", doc |-> doc, root |-> root]
    )
    /\ proofs' = proofs
    /\ lastCommitted' = committed
    /\ lastLedger' = ledger

IssueProof(p) ==
    /\ p \in ProofUniverse
    /\ committed[p.doc] = p.root
    /\ p \notin proofs
    /\ committed' = committed
    /\ ledger' = Append(
        ledger,
        [kind |-> "proof", doc |-> p.doc, root |-> p.root, revealed |-> p.revealed]
    )
    /\ proofs' = proofs \cup {p}
    /\ lastCommitted' = committed
    /\ lastLedger' = ledger

Next ==
    \/ \E doc \in DocIds, root \in Roots: Commit(doc, root)
    \/ \E p \in ProofUniverse: IssueProof(p)

Spec == Init /\ [][Next]_vars

CommittedDocsDoNotChange ==
    \A doc \in DocIds:
        lastCommitted[doc] # Uncommitted => committed[doc] = lastCommitted[doc]

ValidProofsCorrespondToCommittedDocs ==
    \A p \in proofs: committed[p.doc] = p.root

AppendOnlyLedger == IsPrefix(lastLedger, ledger)

=============================================================================
