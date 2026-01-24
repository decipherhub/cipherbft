//! Unit tests for WebSocket pub/sub subscriptions.

use std::sync::Arc;

use cipherbft_rpc::{EthPubSubApi, SubscriptionKind, SubscriptionManager};

/// Test subscription kind variants.
#[test]
fn test_subscription_kind_new_heads() {
    let kind = SubscriptionKind::NewHeads;
    assert!(matches!(kind, SubscriptionKind::NewHeads));
}

/// Test subscription kind for pending transactions (hash-only mode).
#[test]
fn test_subscription_kind_pending_transactions() {
    let kind = SubscriptionKind::NewPendingTransactions {
        full_transactions: false,
    };
    assert!(matches!(
        kind,
        SubscriptionKind::NewPendingTransactions { full_transactions: false }
    ));
}

/// Test subscription kind for pending transactions (full mode).
#[test]
fn test_subscription_kind_pending_transactions_full() {
    let kind = SubscriptionKind::NewPendingTransactions {
        full_transactions: true,
    };
    assert!(matches!(
        kind,
        SubscriptionKind::NewPendingTransactions { full_transactions: true }
    ));
}

/// Test subscription manager creation.
#[test]
fn test_subscription_manager_new() {
    let manager = SubscriptionManager::new();
    assert_eq!(manager.subscription_count(), 0);
}

/// Test subscription manager default.
#[test]
fn test_subscription_manager_default() {
    let manager = SubscriptionManager::default();
    assert_eq!(manager.subscription_count(), 0);
}

/// Test EthPubSubApi creation.
#[test]
fn test_eth_pubsub_api_new() {
    let manager = Arc::new(SubscriptionManager::default());
    let _api = EthPubSubApi::new(manager);
    // API created successfully
}

/// Test subscription creation and counting.
#[test]
fn test_subscription_create() {
    let manager = SubscriptionManager::default();

    let id1 = manager.subscribe(SubscriptionKind::NewHeads);
    assert_eq!(manager.subscription_count(), 1);

    let id2 = manager.subscribe(SubscriptionKind::NewPendingTransactions {
        full_transactions: false,
    });
    assert_eq!(manager.subscription_count(), 2);

    // IDs should be unique
    assert_ne!(id1.as_u64(), id2.as_u64());
}

/// Test unsubscribe removes subscription.
#[test]
fn test_subscription_unsubscribe() {
    let manager = SubscriptionManager::default();

    let id = manager.subscribe(SubscriptionKind::NewHeads);
    assert_eq!(manager.subscription_count(), 1);

    // First unsubscribe should succeed
    assert!(manager.unsubscribe(id));
    assert_eq!(manager.subscription_count(), 0);

    // Second unsubscribe should fail (already removed)
    assert!(!manager.unsubscribe(id));
}

/// Test subscription ID display format.
#[test]
fn test_subscription_id_display() {
    let manager = SubscriptionManager::default();
    let id = manager.subscribe(SubscriptionKind::NewHeads);

    // Display format should be hex (0x prefix)
    let display = format!("{}", id);
    assert!(display.starts_with("0x"));
}

/// Test multiple subscriptions of same kind.
#[test]
fn test_multiple_subscriptions_same_kind() {
    let manager = SubscriptionManager::default();

    let id1 = manager.subscribe(SubscriptionKind::NewHeads);
    let id2 = manager.subscribe(SubscriptionKind::NewHeads);
    let id3 = manager.subscribe(SubscriptionKind::NewHeads);

    assert_eq!(manager.subscription_count(), 3);
    assert_ne!(id1.as_u64(), id2.as_u64());
    assert_ne!(id2.as_u64(), id3.as_u64());

    // Unsubscribe middle one
    manager.unsubscribe(id2);
    assert_eq!(manager.subscription_count(), 2);
}
