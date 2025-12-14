from protocol.policy import Policy, compute_waterfall


def test_policy_waterfall_golden():
    policy = Policy(
        policy_id="base",
        version="1",
        ops_cap_cents=200_000,
        rnd_cap_cents=100_000,
        architect_pct=0.10,
        fund_pct=0.10,
        effective_ts="2025-01-01T00:00:00Z",
    )

    allocations = compute_waterfall(1_000_000, policy)
    assert policy.compute_hash() == "bc7f945b4977b2c8e069cdb07b221b61790e51b2e6edc349f39efb04a33410ac"

    assert allocations == {
        "revenue_cents": 1_000_000,
        "ops_cents": 200_000,
        "architect_cents": 80_000,
        "fund_cents": 620_000,
        "rnd_cents": 100_000,
        "remainder_cents": 548_000,
        "policy_hash": "bc7f945b4977b2c8e069cdb07b221b61790e51b2e6edc349f39efb04a33410ac",
    }
