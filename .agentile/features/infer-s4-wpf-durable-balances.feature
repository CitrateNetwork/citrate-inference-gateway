Feature: API-key balances survive a gateway restart (INFER-S4 / WP-F, slice F1)
  As an institutional buyer billed in SALT
  So that I can trust a stateful gateway with my money
  Balance debits and refunds are durable and apply exactly once across a crash

  # Refines the durable-balance half of
  # citrate-federation/.agentile/gtm-spine/features/INFER-S4-persistence-recovery.feature
  # Source money-flow (gateway@f1f738f): debit auth.rs:354, refund auth.rs:400/422,
  # batch refund batch.rs:469; in-memory store ApiKeyStore::new() lib.rs:117,158.
  # Convergence (TD-23): balance folded into the persistent RocksDB KeyRecord.

  Background:
    Given a gateway whose API-key store is opened on a durable path
    And a key funded with 100 SALT

  Scenario: a committed debit survives a restart, applied exactly once
    Given the key is debited 30 SALT
    When the gateway process is killed and restarted on the same path
    Then the key balance is 70 SALT
    And it is neither 100 (lost debit) nor 40 (double-applied)

  Scenario: a balance is consistent across restart
    Given several debits and refunds are committed
    When the gateway restarts
    Then the balance equals start minus net-debited, exactly

  Scenario: concurrent debits never overspend
    Given many concurrent debits race against the same funded key
    Then the sum of successful debits never exceeds the starting balance
    And the final balance equals start minus the sum of successful debits
    And no debit is lost or double-counted

  Scenario: an insufficient debit changes nothing
    Given a debit larger than the balance
    Then it is refused
    And the persisted balance is unchanged

  Scenario: a refund credits even a revoked key, durably
    Given a key that was debited then revoked
    When it is refunded and the gateway restarts
    Then the refunded amount is reflected in the persisted balance
    # revocation stops future spend but must not trap already-debited funds

  Scenario: the durable store never holds a plaintext bearer
    Given a key minted on the durable store
    Then the on-disk schema is keyed only by sha256(bearer)
    And the plaintext cgk_ token appears nowhere on disk

  Scenario: production marketplace boot refuses a volatile money store
    Given the gateway boots in marketplace mode
    Then the API-key balance store is the durable (persistent) backend
    And a CI tripwire fails if it is constructed in-memory in production
