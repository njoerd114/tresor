//! Boundary-parsed data models returned by the Vault API.
//!
//! Parse-don't-validate: these types are produced exactly once, at the vault-client
//! boundary, from raw API responses. The rest of the app never touches
//! `serde_json::Value` or untyped maps.
//!
//! Value semantics mirror the Go vaultview: secret values are coerced to display
//! strings (Go JSON-marshals each value then unquotes it), and edits write string
//! values back — including the original Go wart that JSON values become strings
//! after an edit round-trip.

use std::collections::BTreeMap;

use secrecy::SecretString;

use crate::path::SecretPath;

/// A single ACL policy entry from `sys/policies/acl` listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEntry {
    /// Policy name.
    pub name: String,
}

/// ACL policy document read from `sys/policies/acl/{name}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDocument {
    /// Policy name.
    pub name: String,
    /// Policy `HCL` text.
    pub policy: String,
}

/// A single item in a KV2 list response. Directory entries keep their trailing `/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretEntry {
    /// The entry name (with trailing `/` for directories).
    pub name: SecretPath,
    /// True for directory entries.
    pub is_dir: bool,
}

impl SecretEntry {
    /// Builds a directory entry from a raw name (must end with `/`).
    #[must_use]
    pub fn dir(name: &str) -> Self {
        Self {
            name: SecretPath::new(name),
            is_dir: true,
        }
    }

    /// Builds a leaf entry from a raw name.
    #[must_use]
    pub fn leaf(name: &str) -> Self {
        Self {
            name: SecretPath::new(name),
            is_dir: false,
        }
    }
}

/// A mounted secret engine together with the metadata needed to browse it safely.
///
/// Vault reports every mount — KV2, KV1, `cubbyhole`, `transit`, PKI, `system`, … —
/// in one list, and only KV2 mounts can be browsed with the KV2 endpoints this app
/// speaks. Keeping the type and version here lets the engines view mark the rest as
/// unsupported instead of letting them fail with a confusing 404.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineInfo {
    /// Mount path with the trailing slash stripped (e.g. `secret`).
    pub name: SecretPath,
    /// Engine type exactly as Vault reports it (`kv`, `cubbyhole`, `transit`, `system`, …).
    pub mount_type: String,
    /// KV engine version when Vault reports one (`Some(2)` for KV2, `Some(1)` for
    /// KV1). `None` for a `kv` mount created without an explicit version — which
    /// the KV backend treats as KV1.
    pub kv_version: Option<u64>,
    /// Opaque engine accessor (safe to display).
    pub accessor: String,
    /// Human-readable mount description (often empty).
    pub description: String,
    /// Default lease TTL in seconds (`0` when the server reports none).
    pub default_lease_ttl: u64,
    /// Maximum lease TTL in seconds (`0` when the server reports none).
    pub max_lease_ttl: u64,
}

impl EngineInfo {
    /// True for a `kv` mount (either version).
    #[must_use]
    pub fn is_kv(&self) -> bool {
        self.mount_type == "kv"
    }

    /// True for a `kv` mount that must be treated as KV1 — an explicit version
    /// `1`, or no version reported at all.
    ///
    /// The KV backend defaults to version 1, so a `kv` mount created without an
    /// explicit version reports **no** `options.version` (`null`) while its type
    /// is still `kv`. Verified on Vault 2.1.2 and `OpenBao` 2.0: such a mount
    /// rejects the KV2 `metadata` endpoint but accepts KV1 reads. Any version
    /// other than `2` is treated as KV1 as well — the rule fails closed.
    #[must_use]
    pub fn is_kv1(&self) -> bool {
        self.is_kv() && self.kv_version != Some(2)
    }

    /// True when the engine can be browsed with the KV2 endpoints.
    ///
    /// Fails closed: only an explicit version `2` is browsable. Treating an
    /// unreported version as KV2 would send `{mount}/metadata/...` requests to a
    /// KV1 mount and produce exactly the confusing 404 this type exists to avoid.
    #[must_use]
    pub fn supports_browsing(&self) -> bool {
        self.is_kv() && self.kv_version == Some(2)
    }

    /// Short display label for the engine type, e.g. `kv v2`, `cubbyhole`, `system`.
    #[must_use]
    pub fn type_label(&self) -> String {
        if !self.is_kv() {
            return self.mount_type.clone();
        }
        match self.kv_version {
            // An unreported version is a KV1 mount (see `is_kv1`).
            None | Some(1) => "kv v1".to_owned(),
            Some(2) => "kv v2".to_owned(),
            Some(other) => format!("kv v{other}"),
        }
    }

    /// One-line reason this engine cannot be browsed, or `None` when it can.
    #[must_use]
    pub fn unsupported_reason(&self) -> Option<String> {
        if self.supports_browsing() {
            return None;
        }
        if self.is_kv() {
            return Some(format!(
                "'{}' is a {} mount; only KV2 engines can be browsed",
                self.name.as_str(),
                self.type_label()
            ));
        }
        Some(format!(
            "'{}' is a '{}' engine; only KV2 engines can be browsed",
            self.name.as_str(),
            self.mount_type
        ))
    }
}

/// A KV2 secret: its key/value data plus version metadata.
#[derive(Debug, Clone)]
pub struct KvData {
    /// Key → display-string value (masks on `Debug`).
    pub data: BTreeMap<String, SecretString>,
    /// Version metadata that accompanies the secret.
    pub metadata: KvMetadata,
}

/// Version metadata returned with a KV2 secret (mirrors `Go` `SecretMetadata`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvMetadata {
    /// Secret version number.
    pub version: u64,
    /// True when the version was destroyed in Vault.
    pub destroyed: bool,
    /// `RFC3339` timestamp as returned by Vault (e.g. `2026-10-13T10:00:00Z`).
    pub created_time: String,
    /// `RFC3339` deletion timestamp; `None` when not soft-deleted.
    pub deletion_time: Option<String>,
}

/// One entry in a KV2 secret's version history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionMeta {
    /// Secret version number.
    pub version: u64,
    /// `RFC3339` creation timestamp (empty string when Vault omits it).
    pub created_time: String,
    /// `RFC3339` deletion timestamp; `None` when the version is not soft-deleted.
    pub deletion_time: Option<String>,
    /// True when the version was destroyed (data permanently gone).
    pub destroyed: bool,
    /// True when this is the secret's current (latest) version.
    pub is_current: bool,
}

/// Full version history for one KV2 secret path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvVersionHistory {
    /// Latest version number (`data.current_version`); 0 when absent.
    pub current_version: u64,
    /// All versions, sorted newest-first.
    pub versions: Vec<VersionMeta>,
}

/// Token lookup info (from `lookup_self`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenInfo {
    /// Policies attached to the token.
    pub policies: Vec<String>,
    /// `None` when the token never expires (`Go` displays "eternal" for root tokens).
    pub expire_time: Option<String>,
    /// Opaque token accessor (safe to display; identifies the token).
    pub accessor: String,
    /// Human-readable token display name.
    pub display_name: String,
    /// Remaining time-to-live in seconds (`0` when the token does not expire).
    pub ttl: u64,
    /// Token creation time as Unix epoch seconds (`0` when unknown).
    pub creation_time: u64,
    /// Whether the token may be renewed.
    pub renewable: bool,
    /// Remaining allowed uses (`0` means unlimited).
    pub num_uses: u64,
    /// Whether the token was created without a parent.
    pub orphan: bool,
}

impl TokenInfo {
    /// True when the token lives forever (`Go`: nil `expire_time` + root policy).
    #[must_use]
    pub fn is_eternal(&self) -> bool {
        self.expire_time.is_none() && self.policies.iter().any(|p| p == "root")
    }
}

/// Parameters for creating a child token (`auth/token/create`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenCreateRequest {
    /// Policies to attach to the child token.
    pub policies: Vec<String>,
    /// Requested TTL as a Vault duration string (e.g. `1h`); `None` uses the default.
    pub ttl: Option<String>,
    /// Maximum number of uses (`None` means unlimited).
    pub num_uses: Option<u64>,
}

/// A freshly minted child token. The token value is shown once and never stored.
#[derive(Debug, Clone)]
pub struct MintedToken {
    /// The secret token value (shown once, then discarded by the UI).
    pub token: SecretString,
    /// Accessor for the minted token (safe to retain/display).
    pub accessor: String,
    /// Policies attached to the minted token.
    pub policies: Vec<String>,
    /// Lease duration in seconds (`None` when the server did not report one).
    pub ttl: Option<u64>,
    /// Whether the minted token is renewable.
    pub renewable: bool,
}

/// A wrapping token returned by `sys/wrapping/wrap` (shown once).
#[derive(Debug, Clone)]
pub struct WrappedToken {
    /// The wrapping token value (shown once, then discarded by the UI).
    pub token: SecretString,
    /// Accessor for the wrapping token.
    pub accessor: String,
    /// Wrap TTL in seconds as reported by the server.
    pub ttl: u64,
}

/// Snapshot of `/v1/sys/health`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthInfo {
    /// True when the Vault server is sealed.
    pub sealed: bool,
    /// Vault server version, e.g. `1.18.0`.
    pub version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eternal_when_root_without_expiry() {
        let info = TokenInfo {
            policies: vec!["root".into()],
            expire_time: None,
            ..TokenInfo::default()
        };
        assert!(info.is_eternal());
    }

    #[test]
    fn not_eternal_when_expiry_present() {
        let info = TokenInfo {
            policies: vec!["root".into()],
            expire_time: Some("2027-01-01T00:00:00Z".into()),
            ..TokenInfo::default()
        };
        assert!(!info.is_eternal());
    }

    #[test]
    fn not_eternal_for_regular_token() {
        let info = TokenInfo {
            policies: vec!["default".into()],
            expire_time: None,
            ..TokenInfo::default()
        };
        assert!(!info.is_eternal());
    }

    #[test]
    fn entry_kinds() {
        let d = SecretEntry::dir("team/");
        assert!(d.is_dir);
        let l = SecretEntry::leaf("creds");
        assert!(!l.is_dir);
    }

    fn engine(name: &str, mount_type: &str, version: Option<u64>) -> EngineInfo {
        EngineInfo {
            name: SecretPath::new(name),
            mount_type: mount_type.to_owned(),
            kv_version: version,
            accessor: format!("{mount_type}_accessor"),
            description: String::new(),
            default_lease_ttl: 0,
            max_lease_ttl: 0,
        }
    }

    #[test]
    fn kv2_engine_is_browsable_with_version_label() {
        let kv2 = engine("secret", "kv", Some(2));
        assert!(kv2.is_kv());
        assert!(!kv2.is_kv1());
        assert!(kv2.supports_browsing());
        assert_eq!(kv2.type_label(), "kv v2");
        assert_eq!(kv2.unsupported_reason(), None);
    }

    #[test]
    fn kv_engine_without_reported_version_is_kv1_and_not_browsable() {
        // Vault/OpenBao report no `options.version` for a `kv` mount created
        // without an explicit version, and such a mount is KV1.
        let unversioned = engine("secret", "kv", None);
        assert!(unversioned.is_kv());
        assert!(unversioned.is_kv1());
        assert!(!unversioned.supports_browsing());
        assert_eq!(unversioned.type_label(), "kv v1");
        assert_eq!(
            unversioned.unsupported_reason().as_deref(),
            Some("'secret' is a kv v1 mount; only KV2 engines can be browsed")
        );
    }

    #[test]
    fn kv1_engine_is_unsupported_with_a_v1_reason() {
        let kv1 = engine("legacy", "kv", Some(1));
        assert!(kv1.is_kv1());
        assert!(!kv1.supports_browsing());
        assert_eq!(kv1.type_label(), "kv v1");
        assert_eq!(
            kv1.unsupported_reason().as_deref(),
            Some("'legacy' is a kv v1 mount; only KV2 engines can be browsed")
        );
    }

    #[test]
    fn non_kv_engine_is_unsupported_and_keeps_its_type_label() {
        let cubbyhole = engine("cubbyhole", "cubbyhole", None);
        assert!(!cubbyhole.supports_browsing());
        assert_eq!(cubbyhole.type_label(), "cubbyhole");
        assert_eq!(
            cubbyhole.unsupported_reason().as_deref(),
            Some("'cubbyhole' is a 'cubbyhole' engine; only KV2 engines can be browsed")
        );
    }
}
