//! Generation-tagged in-memory cache for vault load results.

use std::collections::HashMap;

use crate::model::{
    EngineInfo, HealthInfo, KvData, KvVersionHistory, MintedToken, PolicyDocument, PolicyEntry,
    SecretEntry, TokenInfo, WrappedToken,
};
use crate::path::SecretPath;

/// Composite key for a cached listing: mount engine plus relative KV path.
#[allow(
    clippy::exhaustive_structs,
    reason = "cache keys are value objects with exactly mount and path coordinates"
)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// Mounted KV2 engine path.
    pub mount: SecretPath,
    /// Relative path inside the mounted KV2 engine.
    pub path: SecretPath,
}

/// Loaded data sent from background vault tasks into the UI cache fold.
#[allow(
    clippy::exhaustive_enums,
    reason = "closed message protocol; Store::apply must handle every cache message exhaustively"
)]
#[derive(Debug, Clone)]
pub enum Msg {
    /// Secret engines were loaded.
    EnginesLoaded {
        /// Generation stamped when the background task was spawned.
        generation: u64,
        /// Loaded engine entries.
        entries: Vec<EngineInfo>,
    },
    /// A secret listing was loaded.
    SecretsLoaded {
        /// Generation stamped when the background task was spawned.
        generation: u64,
        /// Cache key for the listing.
        key: CacheKey,
        /// Loaded child entries.
        entries: Vec<SecretEntry>,
    },
    /// A secret value was loaded.
    SecretLoaded {
        /// Generation stamped when the background task was spawned.
        generation: u64,
        /// Cache key for the secret.
        key: CacheKey,
        /// Loaded KV2 data.
        data: KvData,
    },
    /// Vault health was loaded for the header.
    HealthLoaded {
        /// Generation stamped when the background task was spawned.
        generation: u64,
        /// Loaded Vault health snapshot.
        info: HealthInfo,
    },
    /// Token info was loaded for the header.
    TokenLoaded {
        /// Generation stamped when the background task was spawned.
        generation: u64,
        /// Loaded token snapshot.
        info: TokenInfo,
    },
    /// A secret was written successfully.
    SecretWritten {
        /// Generation stamped when the background task was spawned.
        generation: u64,
        /// Written secret key.
        key: CacheKey,
    },
    /// A path cache was cleared after hard refresh.
    HardRefreshed {
        /// Generation stamped when the background task was spawned.
        generation: u64,
        /// Cache key cleared by the refresh.
        key: CacheKey,
    },
    /// A path disappeared and should be evicted from cache and parent listing.
    PathNotFound {
        /// Generation stamped when the background task was spawned.
        generation: u64,
        /// Missing path key.
        key: CacheKey,
    },
    /// A background operation failed with a user-facing message.
    Failure {
        /// Generation stamped when the background task was spawned.
        generation: u64,
        /// User-facing failure message.
        message: String,
    },
    /// Token capabilities for a probed path were loaded (action gating).
    Capabilities {
        /// Generation stamped when the background task was spawned.
        generation: u64,
        /// Whether the token may create at the probed path.
        create: bool,
        /// Whether the token may update at the probed path.
        update: bool,
        /// Whether the token may soft-delete at the probed path.
        soft_delete: bool,
        /// Whether the token may metadata-delete at the probed path.
        metadata_delete: bool,
        /// Whether the token may destroy at the probed path.
        destroy: bool,
        /// Whether the token may undelete at the probed path.
        undelete: bool,
    },
    /// A secret was metadata-deleted at the cache key's path.
    SecretMetadataDeleted {
        /// Generation stamped when the background task was spawned.
        generation: u64,
        /// Cache key of the deleted secret.
        key: CacheKey,
    },
    /// A new secret was created at the cache key's path.
    SecretCreated {
        /// Generation stamped when the background task was spawned.
        generation: u64,
        /// Cache key of the created secret.
        key: CacheKey,
    },
    /// KV2 version history metadata was loaded.
    VersionsLoaded {
        /// Generation stamped when the background task was spawned.
        generation: u64,
        /// Cache key of the secret path.
        key: CacheKey,
        /// Loaded version history.
        history: KvVersionHistory,
    },
    /// One specific KV2 version payload was loaded.
    SecretVersionLoaded {
        /// Generation stamped when the background task was spawned.
        generation: u64,
        /// Cache key of the secret path.
        key: CacheKey,
        /// Version number loaded.
        version: u64,
        /// Loaded KV data for this version.
        data: KvData,
    },
    /// The selected secret version was soft-deleted.
    SecretVersionDeleted {
        /// Generation stamped when the background task was spawned.
        generation: u64,
        /// Cache key of the secret path.
        key: CacheKey,
        /// Version number soft-deleted.
        version: u64,
    },
    /// The selected secret version was undeleted.
    SecretVersionUndeleted {
        /// Generation stamped when the background task was spawned.
        generation: u64,
        /// Cache key of the secret path.
        key: CacheKey,
        /// Version number undeleted.
        version: u64,
    },
    /// The selected secret version was destroyed.
    SecretVersionDestroyed {
        /// Generation stamped when the background task was spawned.
        generation: u64,
        /// Cache key of the secret path.
        key: CacheKey,
        /// Version number destroyed.
        version: u64,
    },
    /// The selected secret version was restored as the latest.
    SecretVersionRestored {
        /// Generation stamped when the background task was spawned.
        generation: u64,
        /// Cache key of the secret path.
        key: CacheKey,
        /// Source version that was restored.
        source_version: u64,
    },
    /// The active token was renewed successfully.
    TokenRenewed {
        /// Generation stamped when the background task was spawned.
        generation: u64,
    },
    /// A child token was minted (value shown once; never cached).
    TokenMinted {
        /// Generation stamped when the background task was spawned.
        generation: u64,
        /// The minted token details.
        minted: MintedToken,
    },
    /// Data was wrapped into a wrapping token (shown once; never cached).
    DataWrapped {
        /// Generation stamped when the background task was spawned.
        generation: u64,
        /// The wrapping token details.
        wrapped: WrappedToken,
    },
    /// A wrapping token was unwrapped into a pretty-printed payload.
    DataUnwrapped {
        /// Generation stamped when the background task was spawned.
        generation: u64,
        /// Pretty-printed JSON payload.
        payload: String,
    },
    /// Token-management capabilities for the active token were loaded (action gating).
    TokenCapabilities {
        /// Generation stamped when the background task was spawned.
        generation: u64,
        /// Whether the token may create child tokens (`auth/token/create`).
        can_create: bool,
        /// Whether the token may wrap data (`sys/wrapping/wrap`).
        can_wrap: bool,
    },
    /// ACL policy list was loaded.
    PoliciesLoaded {
        /// Generation stamped when the background task was spawned.
        generation: u64,
        /// Loaded ACL policy entries.
        entries: Vec<PolicyEntry>,
    },
    /// One ACL policy document was loaded.
    PolicyLoaded {
        /// Generation stamped when the background task was spawned.
        generation: u64,
        /// Policy name key.
        name: String,
        /// Loaded policy document.
        document: PolicyDocument,
    },
    /// An ACL policy was written successfully.
    PolicyWritten {
        /// Generation stamped when the background task was spawned.
        generation: u64,
        /// Written policy name.
        name: String,
    },
    /// ACL policy write capability for a policy name.
    PolicyCapabilities {
        /// Generation stamped when the background task was spawned.
        generation: u64,
        /// Policy name that was probed.
        name: String,
        /// Whether this policy is writable.
        writable: bool,
    },
}

/// In-memory cache the renderer folds messages into.
#[derive(Debug, Default, Clone)]
pub struct Store {
    /// Cached secret engines.
    pub engines: Vec<EngineInfo>,
    /// Cached ACL policy list.
    pub policies: Vec<PolicyEntry>,
    secrets: HashMap<CacheKey, Vec<SecretEntry>>,
    policy_documents: HashMap<String, PolicyDocument>,
    generation: u64,
}

impl Store {
    /// Creates an empty cache with generation zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Advances the cache generation and returns the new task stamp.
    pub const fn bump_generation(&mut self) -> u64 {
        self.generation = self.generation.saturating_add(1);
        self.generation
    }

    /// Folds a background message into the cache, returning true when accepted.
    pub fn apply(&mut self, msg: Msg) -> bool {
        let generation = msg.generation();
        if generation != self.generation {
            return false;
        }

        match msg {
            Msg::EnginesLoaded { entries, .. } => {
                self.engines = entries;
                true
            }
            Msg::SecretsLoaded { key, entries, .. } => {
                self.secrets.insert(key, entries);
                true
            }
            Msg::PoliciesLoaded { entries, .. } => {
                self.policies = entries;
                true
            }
            Msg::PolicyLoaded { name, document, .. } => {
                self.policy_documents.insert(name, document);
                true
            }
            Msg::SecretLoaded { .. }
            | Msg::HealthLoaded { .. }
            | Msg::TokenLoaded { .. }
            | Msg::SecretWritten { .. }
            | Msg::Capabilities { .. }
            | Msg::SecretCreated { .. }
            | Msg::SecretMetadataDeleted { .. }
            | Msg::VersionsLoaded { .. }
            | Msg::SecretVersionLoaded { .. }
            | Msg::SecretVersionDeleted { .. }
            | Msg::SecretVersionUndeleted { .. }
            | Msg::SecretVersionDestroyed { .. }
            | Msg::SecretVersionRestored { .. }
            | Msg::TokenRenewed { .. }
            | Msg::TokenMinted { .. }
            | Msg::DataWrapped { .. }
            | Msg::DataUnwrapped { .. }
            | Msg::TokenCapabilities { .. }
            | Msg::PolicyWritten { .. }
            | Msg::PolicyCapabilities { .. } => true,
            Msg::HardRefreshed { key, .. } => {
                self.secrets.remove(&key);
                true
            }
            Msg::PathNotFound { key, .. } => {
                self.evict_not_found(&key);
                true
            }
            Msg::Failure { .. } => false,
        }
    }

    /// Returns the current generation (stamp for tasks that must not supersede it).
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Clears cached engines and listings without resetting the generation, so
    /// results still in flight from a previous connection are dropped as stale.
    pub fn clear_cached_data_preserving_generation(&mut self) {
        self.engines.clear();
        self.secrets.clear();
    }

    /// Returns the cached secret engines.
    #[must_use]
    pub fn engines(&self) -> &[EngineInfo] {
        &self.engines
    }

    /// Returns the cached ACL policy list.
    #[must_use]
    pub fn policies(&self) -> &[PolicyEntry] {
        &self.policies
    }

    /// Returns a cached child listing by key.
    #[must_use]
    pub fn secrets(&self, key: &CacheKey) -> Option<&[SecretEntry]> {
        self.secrets.get(key).map(Vec::as_slice)
    }

    /// Returns a cached ACL policy document by name.
    #[must_use]
    pub fn policy_document(&self, name: &str) -> Option<&PolicyDocument> {
        self.policy_documents.get(name)
    }

    fn evict_not_found(&mut self, key: &CacheKey) {
        self.secrets.remove(key);

        let parent_key = CacheKey {
            mount: key.mount.clone(),
            path: key.path.parent(),
        };
        let child_name = key.path.child_name();

        if let Some(entries) = self.secrets.get_mut(&parent_key) {
            entries.retain(|entry| entry.name != child_name);
        }
    }
}

impl Msg {
    pub(crate) const fn generation(&self) -> u64 {
        match self {
            Self::EnginesLoaded { generation, .. }
            | Self::SecretsLoaded { generation, .. }
            | Self::SecretLoaded { generation, .. }
            | Self::HealthLoaded { generation, .. }
            | Self::TokenLoaded { generation, .. }
            | Self::SecretWritten { generation, .. }
            | Self::Capabilities { generation, .. }
            | Self::SecretCreated { generation, .. }
            | Self::SecretMetadataDeleted { generation, .. }
            | Self::VersionsLoaded { generation, .. }
            | Self::SecretVersionLoaded { generation, .. }
            | Self::SecretVersionDeleted { generation, .. }
            | Self::SecretVersionUndeleted { generation, .. }
            | Self::SecretVersionDestroyed { generation, .. }
            | Self::SecretVersionRestored { generation, .. }
            | Self::TokenRenewed { generation, .. }
            | Self::TokenMinted { generation, .. }
            | Self::DataWrapped { generation, .. }
            | Self::DataUnwrapped { generation, .. }
            | Self::TokenCapabilities { generation, .. }
            | Self::PoliciesLoaded { generation, .. }
            | Self::PolicyLoaded { generation, .. }
            | Self::PolicyWritten { generation, .. }
            | Self::PolicyCapabilities { generation, .. }
            | Self::HardRefreshed { generation, .. }
            | Self::PathNotFound { generation, .. }
            | Self::Failure { generation, .. } => *generation,
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::{CacheKey, Msg, Store};
    use crate::model::{EngineInfo, KvData, KvMetadata, KvVersionHistory, SecretEntry};
    use crate::path::SecretPath;

    fn key(path: &str) -> CacheKey {
        CacheKey {
            mount: SecretPath::new("secret/"),
            path: SecretPath::new(path),
        }
    }

    fn engine(name: &str) -> EngineInfo {
        EngineInfo {
            name: SecretPath::new(name),
            mount_type: "kv".to_owned(),
            kv_version: Some(2),
            accessor: String::new(),
            description: String::new(),
            default_lease_ttl: 0,
            max_lease_ttl: 0,
        }
    }

    fn load_secrets(store: &mut Store, generation: u64, key: CacheKey, entries: Vec<SecretEntry>) {
        assert!(store.apply(Msg::SecretsLoaded {
            generation,
            key,
            entries,
        }));
    }

    #[test]
    fn apply_when_generation_is_stale_drops_message() {
        let mut store = Store::new();
        let current = store.bump_generation();

        let stale = store.apply(Msg::EnginesLoaded {
            generation: current - 1,
            entries: vec![engine("kv")],
        });
        let accepted = store.apply(Msg::EnginesLoaded {
            generation: current,
            entries: vec![engine("secret")],
        });

        assert!(!stale);
        assert!(accepted);
        assert_eq!(store.engines(), &[engine("secret")]);
    }

    #[test]
    fn secrets_loaded_when_current_generation_stores_by_key() {
        let mut store = Store::new();
        let generation = store.bump_generation();
        let cache_key = key("team/");
        let entries = vec![SecretEntry::leaf("password")];

        load_secrets(&mut store, generation, cache_key.clone(), entries.clone());

        assert_eq!(store.secrets(&cache_key), Some(entries.as_slice()));
    }

    #[test]
    fn hard_refreshed_when_current_generation_clears_only_target_key() {
        let mut store = Store::new();
        let generation = store.bump_generation();
        let target = key("team/");
        let sibling = key("shared/");

        load_secrets(
            &mut store,
            generation,
            target.clone(),
            vec![SecretEntry::leaf("one")],
        );
        load_secrets(
            &mut store,
            generation,
            sibling.clone(),
            vec![SecretEntry::leaf("two")],
        );

        assert!(store.apply(Msg::HardRefreshed {
            generation,
            key: target.clone(),
        }));

        assert_eq!(store.secrets(&target), None);
        assert_eq!(
            store.secrets(&sibling),
            Some([SecretEntry::leaf("two")].as_slice())
        );
    }

    #[test]
    fn clear_cached_data_preserving_generation_keeps_generation_and_drops_stale() {
        let mut store = Store::new();
        let generation = store.bump_generation();
        load_secrets(
            &mut store,
            generation,
            key("team/"),
            vec![SecretEntry::leaf("one")],
        );
        assert!(store.apply(Msg::EnginesLoaded {
            generation,
            entries: vec![engine("secret")],
        }));

        store.clear_cached_data_preserving_generation();

        assert_eq!(store.engines(), []);
        assert_eq!(store.secrets(&key("team/")), None);
        assert_eq!(store.generation(), generation);
        assert!(!store.apply(Msg::EnginesLoaded {
            generation: generation - 1,
            entries: Vec::new(),
        }));
    }

    #[test]
    fn path_not_found_evicts_child_cache_and_parent_entry() {
        let mut store = Store::new();
        let generation = store.bump_generation();
        let parent = key("team/");
        let child = key("team/deleted/");

        load_secrets(
            &mut store,
            generation,
            parent.clone(),
            vec![SecretEntry::dir("deleted/"), SecretEntry::leaf("kept")],
        );
        load_secrets(
            &mut store,
            generation,
            child.clone(),
            vec![SecretEntry::leaf("stale")],
        );

        assert!(store.apply(Msg::PathNotFound {
            generation,
            key: child.clone(),
        }));

        assert_eq!(store.secrets(&child), None);
        assert_eq!(
            store.secrets(&parent),
            Some([SecretEntry::leaf("kept")].as_slice())
        );
    }

    #[test]
    fn engines_loaded_replaces_engines() {
        let mut store = Store::new();
        let generation = store.bump_generation();

        assert!(store.apply(Msg::EnginesLoaded {
            generation,
            entries: vec![engine("old")],
        }));
        assert!(store.apply(Msg::EnginesLoaded {
            generation,
            entries: vec![engine("new")],
        }));

        assert_eq!(store.engines(), &[engine("new")]);
    }

    #[test]
    fn failure_is_not_cache_relevant() {
        let mut store = Store::new();
        let generation = store.bump_generation();

        assert!(!store.apply(Msg::Failure {
            generation,
            message: "denied".to_owned(),
        }));
    }

    #[test]
    fn generation_accessor_exposes_message_stamp() {
        let generation = 42;
        let msg = Msg::Failure {
            generation,
            message: String::new(),
        };

        assert_eq!(msg.generation(), generation);
    }

    #[test]
    fn apply_accepts_version_operation_messages_for_current_generation() {
        let mut store = Store::new();
        let generation = store.bump_generation();
        let cache_key = key("team/api");

        assert!(store.apply(Msg::VersionsLoaded {
            generation,
            key: cache_key.clone(),
            history: KvVersionHistory {
                current_version: 3,
                versions: Vec::new(),
            },
        }));
        assert!(store.apply(Msg::SecretVersionLoaded {
            generation,
            key: cache_key.clone(),
            version: 3,
            data: KvData {
                data: std::collections::BTreeMap::new(),
                metadata: KvMetadata {
                    version: 3,
                    destroyed: false,
                    created_time: String::new(),
                    deletion_time: None,
                },
            },
        }));
        assert!(store.apply(Msg::SecretVersionDeleted {
            generation,
            key: cache_key.clone(),
            version: 3,
        }));
        assert!(store.apply(Msg::SecretVersionUndeleted {
            generation,
            key: cache_key.clone(),
            version: 3,
        }));
        assert!(store.apply(Msg::SecretVersionDestroyed {
            generation,
            key: cache_key.clone(),
            version: 3,
        }));
        assert!(store.apply(Msg::SecretVersionRestored {
            generation,
            key: cache_key,
            source_version: 2,
        }));
    }

    #[test]
    fn apply_drops_stale_version_operation_messages() {
        let mut store = Store::new();
        let generation = store.bump_generation();
        let stale_generation = generation.saturating_sub(1);
        let cache_key = key("team/api");

        assert!(!store.apply(Msg::SecretVersionDeleted {
            generation: stale_generation,
            key: cache_key.clone(),
            version: 9,
        }));
        assert!(!store.apply(Msg::SecretVersionUndeleted {
            generation: stale_generation,
            key: cache_key.clone(),
            version: 9,
        }));
        assert!(!store.apply(Msg::SecretVersionDestroyed {
            generation: stale_generation,
            key: cache_key.clone(),
            version: 9,
        }));
        assert!(!store.apply(Msg::SecretVersionRestored {
            generation: stale_generation,
            key: cache_key,
            source_version: 8,
        }));
    }

    proptest! {
        #[test]
        fn hard_refresh_keeps_other_distinct_keys_queryable(names in prop::collection::btree_set("[a-z]{1,8}", 2..8)) {
            let mut store = Store::new();
            let generation = store.bump_generation();
            let keys: Vec<_> = names.iter().map(|name| key(&format!("{name}/"))).collect();

            for cache_key in &keys {
                load_secrets(&mut store, generation, cache_key.clone(), vec![SecretEntry::leaf("value")]);
            }

            let (target, others) = keys.split_first().expect("set has at least two keys");

            let refreshed = store.apply(Msg::HardRefreshed {
                generation,
                key: target.clone(),
            });
            prop_assert!(refreshed);

            prop_assert_eq!(store.secrets(target), None);
            for other in others {
                let expected = [SecretEntry::leaf("value")];
                prop_assert_eq!(store.secrets(other), Some(expected.as_slice()));
            }
        }
    }
}
