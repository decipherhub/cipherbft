//! Database abstraction for the execution layer.
//!
//! This module provides the database layer that implements the `revm::Database` trait,
//! allowing the EVM to read and write account state, code, and storage.

use crate::error::{DatabaseError, Result};
use alloy_primitives::{Address, B256, U256};
use dashmap::DashMap;
use parking_lot::RwLock;
// MIGRATION(revm33): Database traits now in separate crates
// - DatabaseRef still exported from revm
// - Account, AccountInfo, Bytecode moved to revm_state
// - HashMap moved to revm_primitives
use revm::DatabaseRef;
use revm_primitives::HashMap as RevmHashMap;
use revm_state::{Account as RevmAccount, AccountInfo, Bytecode};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Account state information.
#[derive(Debug, Clone, Default)]
pub struct Account {
    /// Account nonce.
    pub nonce: u64,
    /// Account balance.
    pub balance: U256,
    /// Code hash (keccak256 of code).
    pub code_hash: B256,
    /// Storage root (for Merkle Patricia Trie).
    pub storage_root: B256,
}

/// Provider trait for abstracting storage backend.
///
/// This trait allows the execution layer to work with different storage implementations
/// (in-memory, MDBX, etc.) without coupling to a specific backend.
pub trait Provider: Send + Sync {
    /// Get account information.
    fn get_account(&self, address: Address) -> Result<Option<Account>>;

    /// Get contract bytecode by code hash.
    fn get_code(&self, code_hash: B256) -> Result<Option<Bytecode>>;

    /// Get storage slot value.
    fn get_storage(&self, address: Address, slot: U256) -> Result<U256>;

    /// Get block hash by block number.
    fn get_block_hash(&self, number: u64) -> Result<Option<B256>>;

    /// Set account information.
    fn set_account(&self, address: Address, account: Account) -> Result<()>;

    /// Set contract bytecode.
    fn set_code(&self, code_hash: B256, bytecode: Bytecode) -> Result<()>;

    /// Set storage slot value.
    fn set_storage(&self, address: Address, slot: U256, value: U256) -> Result<()>;

    /// Set block hash.
    fn set_block_hash(&self, number: u64, hash: B256) -> Result<()>;

    /// Get multiple accounts in batch (optimization).
    fn get_accounts_batch(&self, addresses: &[Address]) -> Result<Vec<Option<Account>>> {
        addresses.iter().map(|addr| self.get_account(*addr)).collect()
    }
}

/// In-memory provider for testing and development.
///
/// This provider stores all state in memory using concurrent hash maps.
/// It is not persistent and should only be used for testing.
#[derive(Debug, Clone)]
pub struct InMemoryProvider {
    accounts: Arc<DashMap<Address, Account>>,
    code: Arc<DashMap<B256, Bytecode>>,
    storage: Arc<DashMap<(Address, U256), U256>>,
    block_hashes: Arc<DashMap<u64, B256>>,
}

impl InMemoryProvider {
    /// Create a new in-memory provider.
    pub fn new() -> Self {
        Self {
            accounts: Arc::new(DashMap::new()),
            code: Arc::new(DashMap::new()),
            storage: Arc::new(DashMap::new()),
            block_hashes: Arc::new(DashMap::new()),
        }
    }

    /// Create a provider with initial state for testing.
    pub fn with_genesis(genesis_accounts: Vec<(Address, Account)>) -> Self {
        let provider = Self::new();
        for (address, account) in genesis_accounts {
            provider.accounts.insert(address, account);
        }
        provider
    }
}

impl Default for InMemoryProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl Provider for InMemoryProvider {
    fn get_account(&self, address: Address) -> Result<Option<Account>> {
        Ok(self.accounts.get(&address).map(|entry| entry.clone()))
    }

    fn get_code(&self, code_hash: B256) -> Result<Option<Bytecode>> {
        Ok(self.code.get(&code_hash).map(|entry| entry.clone()))
    }

    fn get_storage(&self, address: Address, slot: U256) -> Result<U256> {
        Ok(self
            .storage
            .get(&(address, slot))
            .map(|entry| *entry)
            .unwrap_or(U256::ZERO))
    }

    fn get_block_hash(&self, number: u64) -> Result<Option<B256>> {
        Ok(self.block_hashes.get(&number).map(|entry| *entry))
    }

    fn set_account(&self, address: Address, account: Account) -> Result<()> {
        self.accounts.insert(address, account);
        Ok(())
    }

    fn set_code(&self, code_hash: B256, bytecode: Bytecode) -> Result<()> {
        self.code.insert(code_hash, bytecode);
        Ok(())
    }

    fn set_storage(&self, address: Address, slot: U256, value: U256) -> Result<()> {
        if value.is_zero() {
            self.storage.remove(&(address, slot));
        } else {
            self.storage.insert((address, slot), value);
        }
        Ok(())
    }

    fn set_block_hash(&self, number: u64, hash: B256) -> Result<()> {
        self.block_hashes.insert(number, hash);
        Ok(())
    }
}

/// CipherBFT database implementation that implements revm's Database trait.
///
/// This database provides a caching layer on top of the underlying provider,
/// and tracks pending state changes during block execution.
pub struct CipherBftDatabase<P: Provider> {
    /// Underlying storage provider.
    provider: Arc<P>,

    /// Pending state changes (not yet committed).
    ///
    /// During block execution, changes are accumulated here and only
    /// written to the provider when commit() is called.
    pending_accounts: Arc<RwLock<BTreeMap<Address, Account>>>,
    pending_code: Arc<RwLock<BTreeMap<B256, Bytecode>>>,
    pending_storage: Arc<RwLock<BTreeMap<(Address, U256), U256>>>,

    /// LRU cache for frequently accessed state.
    cache_accounts: Arc<RwLock<lru::LruCache<Address, Option<Account>>>>,
    cache_code: Arc<RwLock<lru::LruCache<B256, Option<Bytecode>>>>,
}

impl<P: Provider> CipherBftDatabase<P> {
    /// Create a new database with the given provider.
    pub fn new(provider: P) -> Self {
        Self {
            provider: Arc::new(provider),
            pending_accounts: Arc::new(RwLock::new(BTreeMap::new())),
            pending_code: Arc::new(RwLock::new(BTreeMap::new())),
            pending_storage: Arc::new(RwLock::new(BTreeMap::new())),
            cache_accounts: Arc::new(RwLock::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(1000).unwrap(),
            ))),
            cache_code: Arc::new(RwLock::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(500).unwrap(),
            ))),
        }
    }

    /// Commit pending changes to the underlying provider.
    pub fn commit(&self) -> Result<()> {
        // Commit accounts
        let accounts = self.pending_accounts.write();
        for (address, account) in accounts.iter() {
            self.provider.set_account(*address, account.clone())?;
        }

        // Commit code
        let code = self.pending_code.write();
        for (code_hash, bytecode) in code.iter() {
            self.provider.set_code(*code_hash, bytecode.clone())?;
        }

        // Commit storage
        let storage = self.pending_storage.write();
        for ((address, slot), value) in storage.iter() {
            self.provider.set_storage(*address, *slot, *value)?;
        }

        Ok(())
    }

    /// Clear pending changes without committing.
    pub fn clear_pending(&self) {
        self.pending_accounts.write().clear();
        self.pending_code.write().clear();
        self.pending_storage.write().clear();
    }

    /// Get account, checking pending changes first, then cache, then provider.
    fn get_account_internal(&self, address: Address) -> Result<Option<Account>> {
        // Check pending changes first
        if let Some(account) = self.pending_accounts.read().get(&address) {
            return Ok(Some(account.clone()));
        }

        // Check cache
        if let Some(cached) = self.cache_accounts.write().get(&address) {
            return Ok(cached.clone());
        }

        // Load from provider
        let account = self.provider.get_account(address)?;

        // Update cache
        self.cache_accounts.write().put(address, account.clone());

        Ok(account)
    }

    /// Get code, checking pending changes first, then cache, then provider.
    fn get_code_internal(&self, code_hash: B256) -> Result<Option<Bytecode>> {
        // Check pending changes first
        if let Some(bytecode) = self.pending_code.read().get(&code_hash) {
            return Ok(Some(bytecode.clone()));
        }

        // Check cache
        if let Some(cached) = self.cache_code.write().get(&code_hash) {
            return Ok(cached.clone());
        }

        // Load from provider
        let bytecode = self.provider.get_code(code_hash)?;

        // Update cache
        self.cache_code.write().put(code_hash, bytecode.clone());

        Ok(bytecode)
    }

    /// Get storage, checking pending changes first, then provider.
    fn get_storage_internal(&self, address: Address, slot: U256) -> Result<U256> {
        // Check pending changes first
        if let Some(value) = self.pending_storage.read().get(&(address, slot)) {
            return Ok(*value);
        }

        // Load from provider
        self.provider.get_storage(address, slot)
    }
}

/// Implement revm's Database trait for reading state.
impl<P: Provider> revm::DatabaseRef for CipherBftDatabase<P> {
    type Error = DatabaseError;

    /// Get basic account information.
    fn basic_ref(&self, address: Address) -> std::result::Result<Option<AccountInfo>, Self::Error> {
        let account = self
            .get_account_internal(address)
            .map_err(|e| DatabaseError::mdbx(e.to_string()))?;

        Ok(account.map(|acc| AccountInfo {
            balance: acc.balance,
            nonce: acc.nonce,
            code_hash: acc.code_hash,
            code: None, // Code is loaded separately via code_by_hash
        }))
    }

    /// Get contract bytecode by hash.
    fn code_by_hash_ref(&self, code_hash: B256) -> std::result::Result<Bytecode, Self::Error> {
        let bytecode = self
            .get_code_internal(code_hash)
            .map_err(|e| DatabaseError::mdbx(e.to_string()))?;

        bytecode.ok_or(DatabaseError::CodeNotFound(code_hash))
    }

    /// Get storage value at a specific slot.
    fn storage_ref(&self, address: Address, index: U256) -> std::result::Result<U256, Self::Error> {
        self.get_storage_internal(address, index)
            .map_err(|e| DatabaseError::mdbx(e.to_string()))
    }

    /// Get block hash by block number.
    fn block_hash_ref(&self, number: u64) -> std::result::Result<B256, Self::Error> {
        let hash = self
            .provider
            .get_block_hash(number)
            .map_err(|e| DatabaseError::mdbx(e.to_string()))?;

        hash.ok_or(DatabaseError::BlockHashNotFound(number))
    }
}

/// Implement revm's Database trait (mutable version) for compatibility.
impl<P: Provider> revm::Database for CipherBftDatabase<P> {
    type Error = DatabaseError;

    /// Get basic account information.
    fn basic(&mut self, address: Address) -> std::result::Result<Option<AccountInfo>, Self::Error> {
        self.basic_ref(address)
    }

    /// Get contract bytecode by hash.
    fn code_by_hash(&mut self, code_hash: B256) -> std::result::Result<Bytecode, Self::Error> {
        self.code_by_hash_ref(code_hash)
    }

    /// Get storage value at a specific slot.
    fn storage(&mut self, address: Address, index: U256) -> std::result::Result<U256, Self::Error> {
        self.storage_ref(address, index)
    }

    /// Get block hash by block number.
    fn block_hash(&mut self, number: u64) -> std::result::Result<B256, Self::Error> {
        self.block_hash_ref(number)
    }
}


/// Implement revm's DatabaseCommit trait for writing state changes.
impl<P: Provider> revm::DatabaseCommit for CipherBftDatabase<P> {
    fn commit(&mut self, changes: RevmHashMap<Address, RevmAccount>) {
        for (address, account) in changes {
            // Update account info
            let acc = Account {
                nonce: account.info.nonce,
                balance: account.info.balance,
                code_hash: account.info.code_hash,
                storage_root: B256::ZERO, // Will be computed during state root computation
            };
            self.pending_accounts.write().insert(address, acc);

            // Store code if present
            if let Some(code) = account.info.code {
                self.pending_code
                    .write()
                    .insert(account.info.code_hash, code);
            }

            // Update storage
            for (slot, value) in account.storage {
                self.pending_storage
                    .write()
                    .insert((address, slot), value.present_value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Bytes;
    use revm::Database; // Import the trait to access methods

    #[test]
    fn test_in_memory_provider_account_operations() {
        let provider = InMemoryProvider::new();

        // Initially no account
        assert!(provider.get_account(Address::ZERO).unwrap().is_none());

        // Set account
        let account = Account {
            nonce: 1,
            balance: U256::from(100),
            code_hash: B256::ZERO,
            storage_root: B256::ZERO,
        };
        provider.set_account(Address::ZERO, account.clone()).unwrap();

        // Get account
        let retrieved = provider.get_account(Address::ZERO).unwrap().unwrap();
        assert_eq!(retrieved.nonce, 1);
        assert_eq!(retrieved.balance, U256::from(100));
    }

    #[test]
    fn test_in_memory_provider_storage() {
        let provider = InMemoryProvider::new();
        let addr = Address::ZERO;
        let slot = U256::from(42);
        let value = U256::from(1337);

        // Initially zero
        assert_eq!(provider.get_storage(addr, slot).unwrap(), U256::ZERO);

        // Set storage
        provider.set_storage(addr, slot, value).unwrap();

        // Get storage
        assert_eq!(provider.get_storage(addr, slot).unwrap(), value);

        // Clear storage (set to zero)
        provider.set_storage(addr, slot, U256::ZERO).unwrap();
        assert_eq!(provider.get_storage(addr, slot).unwrap(), U256::ZERO);
    }

    #[test]
    fn test_in_memory_provider_code() {
        let provider = InMemoryProvider::new();
        let code_hash = B256::from([1u8; 32]);
        let bytecode = Bytecode::new_raw(Bytes::from(vec![0x60, 0x00]));

        // Initially no code
        assert!(provider.get_code(code_hash).unwrap().is_none());

        // Set code
        provider.set_code(code_hash, bytecode.clone()).unwrap();

        // Get code
        let retrieved = provider.get_code(code_hash).unwrap().unwrap();
        assert_eq!(retrieved.bytecode(), bytecode.bytecode());
    }

    #[test]
    fn test_in_memory_provider_block_hash() {
        let provider = InMemoryProvider::new();
        let block_num = 42;
        let hash = B256::from([42u8; 32]);

        // Initially no hash
        assert!(provider.get_block_hash(block_num).unwrap().is_none());

        // Set block hash
        provider.set_block_hash(block_num, hash).unwrap();

        // Get block hash
        assert_eq!(provider.get_block_hash(block_num).unwrap().unwrap(), hash);
    }

    #[test]
    fn test_database_basic() {
        let provider = InMemoryProvider::new();
        let addr = Address::from([1u8; 20]);

        // Set account in provider
        let account = Account {
            nonce: 5,
            balance: U256::from(1000),
            code_hash: B256::ZERO,
            storage_root: B256::ZERO,
        };
        provider.set_account(addr, account).unwrap();

        // Create database
        let mut db = CipherBftDatabase::new(provider);

        // Query via revm Database trait
        let info = db.basic(addr).unwrap().unwrap();
        assert_eq!(info.nonce, 5);
        assert_eq!(info.balance, U256::from(1000));
    }

    #[test]
    fn test_database_storage() {
        let provider = InMemoryProvider::new();
        let addr = Address::from([1u8; 20]);
        let slot = U256::from(10);
        let value = U256::from(999);

        provider.set_storage(addr, slot, value).unwrap();

        let mut db = CipherBftDatabase::new(provider);
        assert_eq!(db.storage(addr, slot).unwrap(), value);
    }

    #[test]
    fn test_database_code_by_hash() {
        let provider = InMemoryProvider::new();
        let code_hash = B256::from([5u8; 32]);
        let bytecode = Bytecode::new_raw(Bytes::from(vec![0x60, 0x01, 0x60, 0x02]));

        provider.set_code(code_hash, bytecode.clone()).unwrap();

        let mut db = CipherBftDatabase::new(provider);
        let retrieved = db.code_by_hash(code_hash).unwrap();
        assert_eq!(retrieved.bytecode(), bytecode.bytecode());
    }

    #[test]
    fn test_database_block_hash() {
        let provider = InMemoryProvider::new();
        let block_num = 100;
        let hash = B256::from([100u8; 32]);

        provider.set_block_hash(block_num, hash).unwrap();

        let mut db = CipherBftDatabase::new(provider);
        assert_eq!(db.block_hash(block_num).unwrap(), hash);
    }

    #[test]
    fn test_database_block_hash_not_found() {
        let provider = InMemoryProvider::new();
        let mut db = CipherBftDatabase::new(provider);

        let result = db.block_hash(999);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DatabaseError::BlockHashNotFound(999)));
    }

    #[test]
    fn test_database_pending_changes() {
        let provider = InMemoryProvider::new();
        let db = CipherBftDatabase::new(provider.clone());

        let addr = Address::from([2u8; 20]);
        let account = Account {
            nonce: 10,
            balance: U256::from(5000),
            code_hash: B256::ZERO,
            storage_root: B256::ZERO,
        };

        // Add to pending
        db.pending_accounts.write().insert(addr, account.clone());

        // Should read from pending
        let retrieved = db.get_account_internal(addr).unwrap().unwrap();
        assert_eq!(retrieved.nonce, 10);
        assert_eq!(retrieved.balance, U256::from(5000));

        // Not yet in provider
        assert!(provider.get_account(addr).unwrap().is_none());

        // Commit
        db.commit().unwrap();

        // Now in provider
        let provider_account = provider.get_account(addr).unwrap().unwrap();
        assert_eq!(provider_account.nonce, 10);
        assert_eq!(provider_account.balance, U256::from(5000));
    }

    #[test]
    fn test_database_cache() {
        let provider = InMemoryProvider::new();
        let addr = Address::from([3u8; 20]);

        let account = Account {
            nonce: 7,
            balance: U256::from(3000),
            code_hash: B256::ZERO,
            storage_root: B256::ZERO,
        };
        provider.set_account(addr, account).unwrap();

        let db = CipherBftDatabase::new(provider);

        // First access - loads from provider and caches
        let acc1 = db.get_account_internal(addr).unwrap().unwrap();
        assert_eq!(acc1.nonce, 7);

        // Second access - should hit cache
        let acc2 = db.get_account_internal(addr).unwrap().unwrap();
        assert_eq!(acc2.nonce, 7);

        // Verify cache contains the entry
        assert!(db.cache_accounts.write().contains(&addr));
    }
}
