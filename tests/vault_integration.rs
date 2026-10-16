#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::needless_pass_by_value,
    reason = "integration tests document behavior through Given/When/Then names; shared helpers outside #[test] bodies are not covered by clippy.toml allow-*-in-tests"
)]

use std::collections::BTreeMap;

use secrecy::ExposeSecret as _;
use serde_json::{Value, json};
use tresor::model::{
    EngineInfo, HealthInfo, MintedToken, PolicyDocument, PolicyEntry, SecretEntry,
    TokenCreateRequest, WrappedToken,
};
use tresor::path::SecretPath;
use tresor::vault::{VaultApi as _, VaultClient, VaultError};
use wiremock::matchers::{body_partial_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "dev-token";

fn vault_client(server: &MockServer) -> VaultClient {
    VaultClient::connect(&server.uri(), TOKEN).expect("wiremock URL should build a client")
}

fn vault_header() -> impl wiremock::Match {
    header("X-Vault-Token", TOKEN)
}

fn mount_response(mount_type: &str, version: Option<&str>) -> Value {
    json!({
        "accessor": format!("{mount_type}_accessor"),
        "config": {"default_lease_ttl": 3600, "force_no_cache": false, "max_lease_ttl": 7200},
        "description": format!("{mount_type} mount"),
        "external_entropy_access": false,
        "local": false,
        "options": version.map(|v| json!({"version": v})),
        "seal_wrap": false,
        "type": mount_type,
        "uuid": format!("{mount_type}-uuid")
    })
}

#[tokio::test]
async fn read_secret_engines_when_mounts_exist_returns_type_and_metadata() {
    // Given: Vault exposes a KV2 mount, a non-KV mount, and the shape
    // `vault secrets enable kv` produces (type `kv`, `options: null` = KV1).
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/sys/mounts"))
        .and(vault_header())
        .respond_with(ResponseTemplate::new(200).set_body_json(vault_data(json!({
            "secret/": mount_response("kv", Some("2")),
            "legacy/": mount_response("kv", None),
            "cubbyhole/": mount_response("cubbyhole", None)
        }))))
        .mount(&server)
        .await;
    let client = vault_client(&server);

    // When: engines are read through the Vault API boundary.
    let engines = client
        .read_secret_engines()
        .await
        .expect("mounts should parse");

    // Then: each mount keeps its type/version/TTL metadata, sorted by name with the
    // trailing slash stripped from the mount path.
    assert_eq!(engines.len(), 3);

    let cubbyhole = engines.first().expect("cubbyhole engine");
    assert_eq!(cubbyhole.name, SecretPath::new("cubbyhole"));
    assert_eq!(cubbyhole.mount_type, "cubbyhole");
    assert_eq!(cubbyhole.kv_version, None);
    assert!(!cubbyhole.supports_browsing());
    assert_eq!(cubbyhole.type_label(), "cubbyhole");

    let legacy = engines.get(1).expect("legacy engine");
    assert_eq!(legacy.name, SecretPath::new("legacy"));
    assert_eq!(legacy.kv_version, None);
    assert!(legacy.is_kv1());
    assert!(!legacy.supports_browsing());
    assert_eq!(legacy.type_label(), "kv v1");

    let secret = engines.get(2).expect("secret engine");
    assert_eq!(
        *secret,
        EngineInfo {
            name: SecretPath::new("secret"),
            mount_type: "kv".to_owned(),
            kv_version: Some(2),
            accessor: "kv_accessor".to_owned(),
            description: "kv mount".to_owned(),
            default_lease_ttl: 3600,
            max_lease_ttl: 7200,
        }
    );
    assert!(secret.supports_browsing());
    assert_eq!(secret.type_label(), "kv v2");
}

#[tokio::test]
async fn sys_health_when_vault_responds_returns_health_info() {
    // Given: Vault health returns the unwrapped sys/health response shape.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .and(vault_header())
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "initialized": true,
            "sealed": false,
            "standby": false,
            "performance_standby": false,
            "replication_performance_mode": "disabled",
            "replication_dr_mode": "disabled",
            "server_time_utc": 1,
            "version": "1.18.0"
        })))
        .mount(&server)
        .await;
    let client = vault_client(&server);

    // When: health is read.
    let health = client.sys_health().await.expect("health should parse");

    // Then: only the UI model fields are retained.
    assert_eq!(
        health,
        HealthInfo {
            sealed: false,
            version: "1.18.0".to_owned()
        }
    );
}

#[tokio::test]
async fn sys_health_when_openbao_omits_vault_fields_still_parses() {
    // Given: OpenBao health omits fields HashiCorp Vault returns (verified against
    // `bao server -dev` 2.0.0-HEAD): no `performance_standby`, no `enterprise`.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .and(vault_header())
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "initialized": true,
            "sealed": false,
            "standby": false,
            "replication_performance_mode": "disabled",
            "replication_dr_mode": "disabled",
            "server_time_utc": 1_791_893_543,
            "version": "2.0.0-HEAD",
            "cluster_name": "vault-cluster",
            "cluster_id": "eb2efcc6"
        })))
        .mount(&server)
        .await;
    let client = vault_client(&server);

    // When: health is read.
    let health = client.sys_health().await.expect("health should parse");

    // Then: the lenient parser still yields the UI model (OpenBao parity).
    assert_eq!(
        health,
        HealthInfo {
            sealed: false,
            version: "2.0.0-HEAD".to_owned()
        }
    );
}

#[tokio::test]
async fn read_token_info_when_expiry_absent_or_present_maps_token_model() {
    // Given: a root token lookup response without an expiration.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/auth/token/lookup-self"))
        .and(vault_header())
        .respond_with(ResponseTemplate::new(200).set_body_json(token_lookup_body(None)))
        .mount(&server)
        .await;
    let client = vault_client(&server);

    // When: token info is read.
    let token = client
        .read_token_info()
        .await
        .expect("token lookup should parse");

    // Then: root tokens without expiration map all token fields and are eternal.
    assert_eq!(token.accessor, "accessor");
    assert_eq!(token.display_name, "root");
    assert!(token.orphan);
    assert_eq!(token.policies, vec!["root".to_owned()]);
    assert_eq!(token.expire_time, None);
    assert!(token.is_eternal());

    // Given: a second Vault returns an explicit token expiration.
    let expiring_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/auth/token/lookup-self"))
        .and(vault_header())
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(token_lookup_body(Some("2026-10-13T10:00:00Z"))),
        )
        .mount(&expiring_server)
        .await;
    let expiring_client = vault_client(&expiring_server);

    // When: expiring token info is read.
    let expiring = expiring_client
        .read_token_info()
        .await
        .expect("token lookup should parse");

    // Then: the expiration is preserved.
    assert_eq!(
        expiring.expire_time.as_deref(),
        Some("2026-10-13T10:00:00Z")
    );
    assert!(!expiring.is_eternal());
}

#[tokio::test]
async fn renew_token_self_when_called_posts_and_succeeds() {
    // Given: Vault renew-self endpoint accepts an authenticated POST.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/auth/token/renew-self"))
        .and(vault_header())
        .respond_with(ResponseTemplate::new(200).set_body_json(vault_data(json!({}))))
        .mount(&server)
        .await;
    let client = vault_client(&server);

    // When: token renewal is requested.
    let result = client.renew_token_self().await;

    // Then: renew-self succeeds.
    assert_eq!(result, Ok(()));
}

#[tokio::test]
async fn create_token_when_called_posts_policies_ttl_and_uses() {
    // Given: Vault token/create expects policies, ttl, and num_uses in the POST body.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/auth/token/create"))
        .and(vault_header())
        .and(body_partial_json(json!({
            "policies": ["default", "app"],
            "ttl": "1h",
            "num_uses": 3
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": {
                "client_token": "hvs.child",
                "accessor": "child-accessor",
                "token_policies": ["default", "app"],
                "lease_duration": 3600,
                "renewable": true
            }
        })))
        .mount(&server)
        .await;
    let client = vault_client(&server);
    let request = TokenCreateRequest {
        policies: vec!["default".to_owned(), "app".to_owned()],
        ttl: Some("1h".to_owned()),
        num_uses: Some(3),
    };

    // When: a child token is created.
    let minted: MintedToken = client
        .create_token(&request)
        .await
        .expect("token create should parse");

    // Then: the minted token model reflects the auth payload.
    assert_eq!(minted.token.expose_secret(), "hvs.child");
    assert_eq!(minted.accessor, "child-accessor");
    assert_eq!(
        minted.policies,
        vec!["default".to_owned(), "app".to_owned()]
    );
    assert_eq!(minted.ttl, Some(3600));
    assert!(minted.renewable);
}

#[tokio::test]
async fn wrap_data_when_called_sends_wrap_ttl_header_and_returns_token() {
    // Given: sys/wrapping/wrap requires wrap-ttl and returns wrap_info token data.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/sys/wrapping/wrap"))
        .and(vault_header())
        .and(header("X-Vault-Wrap-TTL", "5m"))
        .and(body_partial_json(json!({"password": "s3cr3t"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "wrap_info": {
                "token": "hvs.wrap",
                "accessor": "wrap-accessor",
                "ttl": 300
            }
        })))
        .mount(&server)
        .await;
    let client = vault_client(&server);

    // When: payload wrapping is requested with TTL.
    let wrapped: WrappedToken = client
        .wrap_data(&json!({"password": "s3cr3t"}), Some("5m"))
        .await
        .expect("wrap response should parse");

    // Then: the wrap token fields are mapped from wrap_info.
    assert_eq!(wrapped.token.expose_secret(), "hvs.wrap");
    assert_eq!(wrapped.accessor, "wrap-accessor");
    assert_eq!(wrapped.ttl, 300);
}

#[tokio::test]
async fn wrap_data_when_no_ttl_defaults_to_five_minutes() {
    // Given: Vault's sys/wrapping/wrap rejects requests lacking a wrap TTL header.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/sys/wrapping/wrap"))
        .and(vault_header())
        .and(header("X-Vault-Wrap-TTL", "5m"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "wrap_info": {
                "token": "hvs.default",
                "accessor": "wrap-accessor",
                "ttl": 300
            }
        })))
        .mount(&server)
        .await;
    let client = vault_client(&server);

    // When: wrapping is requested without an explicit TTL.
    let wrapped: WrappedToken = client
        .wrap_data(&json!({"k": "v"}), None)
        .await
        .expect("wrap should fall back to the default TTL");

    // Then: the default wrap TTL header was sent and the token is mapped.
    assert_eq!(wrapped.token.expose_secret(), "hvs.default");
}

#[tokio::test]
async fn unwrap_data_when_called_uses_wrapping_token_and_pretty_prints_payload() {
    // Given: unwrap authenticates with the wrapping token and returns a data block.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/sys/wrapping/unwrap"))
        .and(header("X-Vault-Token", "hvs.wrapping"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data": {"password": "hunter2"}})),
        )
        .mount(&server)
        .await;
    let client = vault_client(&server);

    // When: wrapped data is unwrapped.
    let unwrapped = client
        .unwrap_data("hvs.wrapping")
        .await
        .expect("unwrap response should parse");

    // Then: payload JSON is pretty-printed and contains the secret value.
    assert!(unwrapped.contains("hunter2"));
    assert!(unwrapped.contains('\n'));
}

#[tokio::test]
async fn list_kv_secrets_when_root_and_nested_paths_maps_dirs_and_leaves() {
    // Given: Vault KV2 LIST endpoints for root and a nested directory.
    let server = MockServer::start().await;
    Mock::given(method("LIST"))
        .and(path("/v1/secret/metadata/"))
        .and(vault_header())
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(vault_data(json!({"keys": ["team/", "creds"]}))),
        )
        .mount(&server)
        .await;
    Mock::given(method("LIST"))
        .and(path("/v1/secret/metadata/team/"))
        .and(vault_header())
        .respond_with(ResponseTemplate::new(200).set_body_json(vault_data(json!({"keys": ["db"]}))))
        .mount(&server)
        .await;
    let client = vault_client(&server);
    let mount = SecretPath::new("secret");

    // When: root and nested KV paths are listed.
    let root = client
        .list_kv_secrets(&mount, &SecretPath::root())
        .await
        .expect("root list should parse");
    let nested = client
        .list_kv_secrets(&mount, &SecretPath::new("team/"))
        .await
        .expect("nested list should parse");

    // Then: trailing slash keys become directory entries and other keys become leaves.
    assert_eq!(
        root,
        vec![SecretEntry::dir("team/"), SecretEntry::leaf("creds")]
    );
    assert_eq!(nested, vec![SecretEntry::leaf("db")]);
}

#[tokio::test]
async fn list_kv_secrets_when_list_verb_rejected_falls_back_to_get_list_query() {
    // Given: a gateway that refuses the LIST verb (observed 400 over HTTP/1.1)
    // but accepts Vault's/OpenBao's GET ?list=true spelling.
    let server = MockServer::start().await;
    Mock::given(method("LIST"))
        .and(path("/v1/secret/metadata/"))
        .and(vault_header())
        .respond_with(ResponseTemplate::new(400).set_body_string("Bad Request"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/metadata/"))
        .and(query_param("list", "true"))
        .and(vault_header())
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(vault_data(json!({"keys": ["team/", "creds"]}))),
        )
        .mount(&server)
        .await;
    let client = vault_client(&server);

    // When: the KV root is listed.
    let entries = client
        .list_kv_secrets(&SecretPath::new("secret"), &SecretPath::root())
        .await
        .expect("fallback list should parse");

    // Then: the GET ?list=true response is parsed into the same entries.
    assert_eq!(
        entries,
        vec![SecretEntry::dir("team/"), SecretEntry::leaf("creds")]
    );
}

#[tokio::test]
async fn read_kv_secret_when_values_have_mixed_types_coerces_display_strings() {
    // Given: a KV2 secret containing string, number, and boolean JSON values.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/creds"))
        .and(vault_header())
        .respond_with(ResponseTemplate::new(200).set_body_json(vault_data(json!({
            "data": {"user": "alice", "port": 5432, "flag": true},
            "metadata": {"version": 1, "created_time": "2026-10-13T09:00:00Z", "destroyed": false, "deletion_time": "", "custom_metadata": null}
        }))))
        .mount(&server)
        .await;
    let client = vault_client(&server);

    // When: the secret is read.
    let secret = client
        .read_kv_secret(&SecretPath::new("secret"), &SecretPath::new("creds"))
        .await
        .expect("secret should parse");

    // Then: string values are raw strings and non-strings are JSON text.
    assert_eq!(
        secret.data.get("user").expect("user key").expose_secret(),
        "alice"
    );
    assert_eq!(
        secret.data.get("port").expect("port key").expose_secret(),
        "5432"
    );
    assert_eq!(
        secret.data.get("flag").expect("flag key").expose_secret(),
        "true"
    );
    assert_eq!(secret.metadata.version, 1);
    assert_eq!(secret.metadata.created_time, "2026-10-13T09:00:00Z");
}

#[tokio::test]
async fn read_kv_secret_when_openbao_omits_or_nulls_metadata_fields_still_parses() {
    // Given: an OpenBao-shaped response where metadata fields are `null` or
    // missing — Go's json decoder tolerates this; strict serde would reject it.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/creds"))
        .and(vault_header())
        .respond_with(ResponseTemplate::new(200).set_body_json(vault_data(json!({
            "data": {"user": "alice"},
            "metadata": {
                "created_time": null,
                "custom_metadata": null,
                "deletion_time": null,
                "destroyed": null,
                "version": null
            }
        }))))
        .mount(&server)
        .await;
    let client = vault_client(&server);

    // When: the secret is read.
    let secret = client
        .read_kv_secret(&SecretPath::new("secret"), &SecretPath::new("creds"))
        .await
        .expect("secret should parse despite null metadata");

    // Then: values survive and metadata falls back to safe defaults.
    assert_eq!(
        secret.data.get("user").expect("user key").expose_secret(),
        "alice"
    );
    assert_eq!(secret.metadata.version, 0);
    assert!(!secret.metadata.destroyed);
    assert_eq!(secret.metadata.created_time, "");
    assert_eq!(secret.metadata.deletion_time, None);
}

#[tokio::test]
async fn read_kv_metadata_when_versions_object_has_string_keys_sorts_desc_and_marks_current() {
    // Given: KV2 metadata returns versions as string-keyed object entries.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/metadata/creds"))
        .and(vault_header())
        .respond_with(ResponseTemplate::new(200).set_body_json(vault_data(json!({
            "current_version": 2,
            "versions": {
                "1": {
                    "created_time": "2026-10-13T08:00:00Z",
                    "deletion_time": "",
                    "destroyed": false
                },
                "2": {
                    "created_time": "2026-10-13T09:00:00Z",
                    "deletion_time": "",
                    "destroyed": false
                },
                "abc": {
                    "created_time": "ignored",
                    "deletion_time": "",
                    "destroyed": true
                }
            }
        }))))
        .mount(&server)
        .await;
    let client = vault_client(&server);

    // When: metadata is read.
    let history = client
        .read_kv_metadata(&SecretPath::new("secret"), &SecretPath::new("creds"))
        .await
        .expect("metadata should parse");

    // Then: versions are sorted descending, current marked, and non-u64 keys skipped.
    assert_eq!(history.current_version, 2);
    assert_eq!(history.versions.len(), 2);
    let first = history.versions.first().expect("first version");
    let second = history.versions.get(1).expect("second version");
    assert_eq!(first.version, 2);
    assert!(first.is_current);
    assert_eq!(second.version, 1);
    assert!(!second.is_current);
}

#[tokio::test]
async fn read_kv_metadata_when_openbao_nulls_deletion_time_maps_none() {
    // Given: metadata version entries carry null deletion_time.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/metadata/creds"))
        .and(vault_header())
        .respond_with(ResponseTemplate::new(200).set_body_json(vault_data(json!({
            "current_version": 1,
            "versions": {
                "1": {
                    "created_time": "2026-10-13T09:00:00Z",
                    "deletion_time": null,
                    "destroyed": false
                }
            }
        }))))
        .mount(&server)
        .await;
    let client = vault_client(&server);

    // When: metadata is read.
    let history = client
        .read_kv_metadata(&SecretPath::new("secret"), &SecretPath::new("creds"))
        .await
        .expect("metadata should parse");

    // Then: deletion time maps to None.
    assert_eq!(history.versions.len(), 1);
    let single = history.versions.first().expect("single version");
    assert_eq!(single.deletion_time, None);
}

#[tokio::test]
async fn read_kv_version_when_called_sends_version_query_and_parses_data() {
    // Given: KV2 read for a specific version and token header.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/creds"))
        .and(query_param("version", "3"))
        .and(vault_header())
        .respond_with(ResponseTemplate::new(200).set_body_json(vault_data(json!({
            "data": {"user": "alice"},
            "metadata": {
                "version": 3,
                "created_time": "2026-10-13T10:00:00Z",
                "deletion_time": "",
                "destroyed": false
            }
        }))))
        .mount(&server)
        .await;
    let client = vault_client(&server);

    // When: version 3 is read.
    let secret = client
        .read_kv_version(&SecretPath::new("secret"), &SecretPath::new("creds"), 3)
        .await
        .expect("versioned read should parse");

    // Then: query parameter and payload are mapped into KvData.
    assert_eq!(
        secret.data.get("user").expect("user key").expose_secret(),
        "alice"
    );
    assert_eq!(secret.metadata.version, 3);
}

#[tokio::test]
async fn delete_kv_secret_version_when_called_posts_versions_body() {
    // Given: KV2 delete endpoint accepts version array via POST.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/secret/delete/creds"))
        .and(vault_header())
        .and(body_partial_json(json!({"versions": [3]})))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = vault_client(&server);

    // When: version 3 is soft-deleted.
    let result = client
        .delete_kv_secret_version(&SecretPath::new("secret"), &SecretPath::new("creds"), 3)
        .await;

    // Then: request shape matches KV2 contract and succeeds on empty body.
    assert_eq!(result, Ok(()));
}

#[tokio::test]
async fn undelete_kv_secret_version_when_called_posts_versions_body() {
    // Given: KV2 undelete endpoint accepts version array via POST.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/secret/undelete/creds"))
        .and(vault_header())
        .and(body_partial_json(json!({"versions": [3]})))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = vault_client(&server);

    // When: version 3 is undeleted.
    let result = client
        .undelete_kv_secret_version(&SecretPath::new("secret"), &SecretPath::new("creds"), 3)
        .await;

    // Then: request shape matches KV2 contract and succeeds on empty body.
    assert_eq!(result, Ok(()));
}

#[tokio::test]
async fn destroy_kv_secret_version_when_called_puts_versions_body() {
    // Given: KV2 destroy endpoint accepts version array via PUT.
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/v1/secret/destroy/creds"))
        .and(vault_header())
        .and(body_partial_json(json!({"versions": [3]})))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = vault_client(&server);

    // When: version 3 is destroyed.
    let result = client
        .destroy_kv_secret_version(&SecretPath::new("secret"), &SecretPath::new("creds"), 3)
        .await;

    // Then: request shape matches KV2 contract and succeeds on empty body.
    assert_eq!(result, Ok(()));
}

#[tokio::test]
async fn read_kv_secret_when_metadata_has_deletion_time_preserves_it() {
    // Given: KV2 metadata carries a non-empty deletion timestamp.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/creds"))
        .and(vault_header())
        .respond_with(ResponseTemplate::new(200).set_body_json(vault_data(json!({
            "data": {"user": "alice"},
            "metadata": {
                "version": 1,
                "created_time": "2026-10-13T09:00:00Z",
                "deletion_time": "2026-10-14T09:00:00Z",
                "destroyed": false
            }
        }))))
        .mount(&server)
        .await;
    let client = vault_client(&server);

    // When: secret metadata is read.
    let secret = client
        .read_kv_secret(&SecretPath::new("secret"), &SecretPath::new("creds"))
        .await
        .expect("secret should parse");

    // Then: deletion_time is preserved as Some(timestamp).
    assert_eq!(
        secret.metadata.deletion_time.as_deref(),
        Some("2026-10-14T09:00:00Z")
    );
}

#[tokio::test]
async fn delete_kv_secret_metadata_when_called_sends_delete_and_accepts_204() {
    // Given: Vault answers a metadata DELETE with 204 No Content.
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/v1/secret/metadata/creds"))
        .and(vault_header())
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = vault_client(&server);

    // When: the secret metadata is deleted.
    let result = client
        .delete_kv_secret_metadata(&SecretPath::new("secret"), &SecretPath::new("creds"))
        .await;

    // Then: the empty (204) response is accepted as success.
    assert!(result.is_ok());
}

#[tokio::test]
async fn capabilities_self_when_vault_responds_maps_paths_to_capability_lists() {
    // Given: capabilities-self returns the token's caps for a KV2 data path.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/sys/capabilities-self"))
        .and(vault_header())
        .and(body_partial_json(
            json!({"paths": ["secret/data/team/new"]}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(vault_data(json!({
            "secret/data/team/new": ["create", "update", "read"]
        }))))
        .mount(&server)
        .await;
    let client = vault_client(&server);

    // When: capabilities are queried.
    let caps = client
        .capabilities_self(&["secret/data/team/new".to_owned()])
        .await
        .expect("capabilities should parse");

    // Then: the path maps to its capability list (used to gate write commands).
    assert_eq!(
        caps.get("secret/data/team/new"),
        Some(&vec![
            "create".to_owned(),
            "update".to_owned(),
            "read".to_owned()
        ])
    );
}

#[tokio::test]
async fn write_kv_secret_when_called_posts_kv2_data_body_with_token() {
    // Given: Vault expects a KV2 write at the data endpoint with a data object.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/secret/data/creds"))
        .and(vault_header())
        .and(body_partial_json(
            json!({"data": {"user": "tom", "password": "p@ssw0rd"}}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(vault_data(json!({
            "version": 2,
            "created_time": "2026-10-13T09:01:00Z",
            "destroyed": false,
            "deletion_time": "",
            "custom_metadata": null
        }))))
        .mount(&server)
        .await;
    let client = vault_client(&server);
    let data = BTreeMap::from([
        ("password".to_owned(), "p@ssw0rd".to_owned()),
        ("user".to_owned(), "tom".to_owned()),
    ]);

    // When: the secret is written.
    let result = client
        .write_kv_secret(&SecretPath::new("secret"), &SecretPath::new("creds"), &data)
        .await;

    // Then: vaultrs sent the expected request and the write succeeds.
    assert_eq!(result, Ok(()));
}

#[tokio::test]
async fn read_kv_secret_when_vault_returns_404_maps_api_error_status() {
    // Given: Vault returns a JSON API error for a missing secret.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/gone"))
        .and(vault_header())
        .respond_with(
            ResponseTemplate::new(404).set_body_json(json!({"errors": ["no value found"]})),
        )
        .mount(&server)
        .await;
    let client = vault_client(&server);

    // When: the missing secret is read.
    let error = client
        .read_kv_secret(&SecretPath::new("secret"), &SecretPath::new("gone"))
        .await
        .expect_err("missing secret should map to an API error");

    // Then: the status is available to callers for 404 backtracking.
    assert_eq!(error.status(), Some(404));
    assert!(matches!(error, VaultError::Api { status: 404, .. }));
}

fn token_lookup_body(expire_time: Option<&str>) -> Value {
    vault_data(json!({
            "accessor": "accessor",
            "creation_time": 1,
            "creation_ttl": 0,
            "display_name": "root",
            "entity_id": "",
            "expire_time": expire_time,
            "explicit_max_ttl": 0,
            "id": "token-id",
            "identity_policies": null,
            "issue_time": null,
            "meta": null,
            "num_uses": 0,
            "orphan": true,
            "path": "auth/token/root",
            "policies": ["root"],
            "renewable": null,
            "role": null,
            "ttl": 0
    }))
}

fn vault_data(data: Value) -> Value {
    json!({
        "request_id": "request-id",
        "lease_id": "",
        "renewable": false,
        "lease_duration": 0,
        "data": data,
        "warnings": null,
        "wrap_info": null,
        "auth": null
    })
}

#[tokio::test]
async fn list_acl_policies_when_list_succeeds_returns_sorted_entries() {
    let server = MockServer::start().await;
    Mock::given(method("LIST"))
        .and(path("/v1/sys/policies/acl"))
        .and(vault_header())
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(vault_data(json!({"keys": ["team", "default"]}))),
        )
        .mount(&server)
        .await;
    let client = vault_client(&server);

    let policies = client
        .list_acl_policies()
        .await
        .expect("policies should parse");

    assert_eq!(
        policies,
        vec![
            PolicyEntry {
                name: "default".to_owned()
            },
            PolicyEntry {
                name: "team".to_owned()
            }
        ]
    );
}

#[tokio::test]
async fn list_acl_policies_when_list_rejected_falls_back_to_get_list_query() {
    let server = MockServer::start().await;
    Mock::given(method("LIST"))
        .and(path("/v1/sys/policies/acl"))
        .and(vault_header())
        .respond_with(ResponseTemplate::new(400).set_body_string("Bad Request"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/sys/policies/acl"))
        .and(query_param("list", "true"))
        .and(vault_header())
        .respond_with(
            ResponseTemplate::new(200).set_body_json(vault_data(json!({"keys": ["default"]}))),
        )
        .mount(&server)
        .await;
    let client = vault_client(&server);

    let policies = client
        .list_acl_policies()
        .await
        .expect("fallback policies should parse");

    assert_eq!(
        policies,
        vec![PolicyEntry {
            name: "default".to_owned()
        }]
    );
}

#[tokio::test]
async fn read_acl_policy_plain_text_parses() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/sys/policies/acl/team"))
        .and(vault_header())
        .respond_with(ResponseTemplate::new(200).set_body_json(vault_data(json!({
            "name": "team",
            "policy": "path \"secret/data/team/*\" { capabilities = [\"read\"] }"
        }))))
        .mount(&server)
        .await;
    let client = vault_client(&server);

    let policy = client
        .read_acl_policy("team")
        .await
        .expect("policy should parse");

    assert_eq!(
        policy,
        PolicyDocument {
            name: "team".to_owned(),
            policy: "path \"secret/data/team/*\" { capabilities = [\"read\"] }".to_owned()
        }
    );
}

#[tokio::test]
async fn read_acl_policy_base64_prefixed_decodes() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/sys/policies/acl/team"))
        .and(vault_header())
        .respond_with(ResponseTemplate::new(200).set_body_json(vault_data(json!({
            "name": "team",
            "policy": "base64:cGF0aCAic2VjcmV0L2RhdGEvdGVhbS8qIiB7IGNhcGFiaWxpdGllcyA9IFsicmVhZCJdIH0="
        }))))
        .mount(&server)
        .await;
    let client = vault_client(&server);

    let policy = client
        .read_acl_policy("team")
        .await
        .expect("policy should decode");

    assert_eq!(
        policy.policy,
        "path \"secret/data/team/*\" { capabilities = [\"read\"] }"
    );
}

#[tokio::test]
async fn read_acl_policy_missing_maps_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/sys/policies/acl/missing"))
        .and(vault_header())
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"errors": ["not found"]})))
        .mount(&server)
        .await;
    let client = vault_client(&server);

    let error = client
        .read_acl_policy("missing")
        .await
        .expect_err("missing policy should fail");

    assert_eq!(error.status(), Some(404));
}

#[tokio::test]
async fn write_acl_policy_puts_policy_body() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/v1/sys/policies/acl/team"))
        .and(vault_header())
        .and(body_partial_json(json!({"policy": "path \"secret/*\" {}"})))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let client = vault_client(&server);

    let result = client
        .write_acl_policy("team", "path \"secret/*\" {}")
        .await;

    assert_eq!(result, Ok(()));
}

#[tokio::test]
async fn write_acl_policy_403_maps_api_error() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/v1/sys/policies/acl/team"))
        .and(vault_header())
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"errors": ["denied"]})))
        .mount(&server)
        .await;
    let client = vault_client(&server);

    let result = client
        .write_acl_policy("team", "path \"secret/*\" {}")
        .await;

    assert!(matches!(result, Err(VaultError::Api { status: 403, .. })));
}
