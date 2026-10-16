//! `vaultrs`-backed Vault API client.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use base64::Engine as _;
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::Value;
use vaultrs::client::{VaultClient as InnerVaultClient, VaultClientSettingsBuilder};
use vaultrs::error::ClientError;

use super::{VaultApi, VaultError, encode_acl_policy_name};
use crate::constants::NA_VALUE;
use crate::model::{
    EngineInfo, HealthInfo, KvData, KvMetadata, KvVersionHistory, MintedToken, PolicyDocument,
    PolicyEntry, SecretEntry, TokenCreateRequest, TokenInfo, VersionMeta, WrappedToken,
};
use crate::path::SecretPath;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const ERROR_DETAIL_LIMIT: usize = 200;
/// Vault's `sys/wrapping/wrap` endpoint rejects requests without a wrap TTL, so a
/// blank request uses this default (the same 5 minutes the `vault` CLI applies).
const DEFAULT_WRAP_TTL: &str = "5m";

/// Vault client implemented by the `vaultrs` crate, with a direct HTTP
/// fallback for the lenient `/v1/sys/health` probe (`OpenBao` compatibility).
pub struct VaultClient {
    inner: InnerVaultClient,
    addr: String,
    token: SecretString,
    http: reqwest::Client,
}

impl fmt::Debug for VaultClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultClient").finish_non_exhaustive()
    }
}

impl VaultClient {
    /// Builds a Vault/OpenBao client from an HTTP(S) address and token.
    pub fn connect(addr: &str, token: &str) -> Result<Self, VaultError> {
        let settings = VaultClientSettingsBuilder::default()
            .address(addr)
            .token(token)
            .timeout(Some(REQUEST_TIMEOUT))
            .build()
            .map_err(|err| VaultError::Connection(err.to_string()))?;
        let inner = InnerVaultClient::new(settings)
            .map_err(|err| VaultError::Connection(err.to_string()))?;
        Ok(Self {
            inner,
            addr: addr.to_owned(),
            token: SecretString::from(token),
            http: reqwest::Client::new(),
        })
    }

    async fn with_timeout<T>(
        future: impl std::future::Future<Output = Result<T, ClientError>>,
        path: &str,
    ) -> Result<T, VaultError> {
        tokio::time::timeout(REQUEST_TIMEOUT, future)
            .await
            .map_or_else(
                |_| Err(VaultError::Connection("timed out".to_owned())),
                |result| result.map_err(|err| map_client_error(err, path)),
            )
    }

    /// Sends a raw Vault/OpenBao request and returns the JSON envelope.
    ///
    /// The body is read as text first, then parsed: Vault error envelopes carry
    /// the detail in `errors[0]`, but a gateway may answer an error status with
    /// a non-JSON body (e.g. a `text/plain` 400) — that raw text becomes the
    /// error detail instead of a misattributed JSON decode failure.
    async fn raw_json(
        http: reqwest::Client,
        url: &str,
        method: reqwest::Method,
        token: &str,
        error_path: &str,
    ) -> Result<Value, VaultError> {
        Self::raw_request(
            http.request(method, url).header("X-Vault-Token", token),
            error_path,
        )
        .await
    }

    /// POSTs a JSON body and returns the JSON envelope (same lenient rules).
    async fn raw_json_post(
        http: reqwest::Client,
        url: &str,
        token: &str,
        error_path: &str,
        body: &Value,
    ) -> Result<Value, VaultError> {
        Self::raw_json_body(http, url, reqwest::Method::POST, token, error_path, body).await
    }

    /// Sends a request with a JSON body and returns the JSON envelope.
    async fn raw_json_body(
        http: reqwest::Client,
        url: &str,
        method: reqwest::Method,
        token: &str,
        error_path: &str,
        body: &Value,
    ) -> Result<Value, VaultError> {
        Self::raw_request(
            http.request(method, url)
                .header("X-Vault-Token", token)
                .json(body),
            error_path,
        )
        .await
    }

    /// Sends a prepared request and returns the parsed envelope or a typed error.
    ///
    /// The body is read as text first, then parsed: Vault error envelopes carry
    /// the detail in `errors[0]`, but a gateway may answer an error status with
    /// a non-JSON body (e.g. a `text/plain` 400) — that raw text becomes the
    /// error detail instead of a misattributed JSON decode failure.
    async fn raw_request(
        request: reqwest::RequestBuilder,
        error_path: &str,
    ) -> Result<Value, VaultError> {
        let response = tokio::time::timeout(REQUEST_TIMEOUT, request.send())
            .await
            .map_err(|_| VaultError::Connection("timed out".to_owned()))?
            .map_err(|err| VaultError::Connection(err.to_string()))?;
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|err| VaultError::Connection(err.to_string()))?;
        if status.is_success() {
            if text.trim().is_empty() {
                // 204 No Content (e.g. KV2 metadata delete) has no envelope.
                return Ok(Value::Null);
            }
            return serde_json::from_str(&text).map_err(|err| VaultError::Parse(err.to_string()));
        }
        let detail = serde_json::from_str::<Value>(&text).map_or_else(
            // Non-JSON error body (e.g. a gateway's text/plain 400): use the raw
            // text as the detail instead of a misattributed JSON decode failure.
            |_| truncate_detail(&text),
            |body| error_detail_from_body(&body),
        );
        Err(VaultError::Api {
            status: status.as_u16(),
            path: error_path.to_owned(),
            detail,
        })
    }
}

#[allow(
    clippy::manual_async_fn,
    reason = "VaultApi futures must be Send for tokio::spawn; async fn cannot express that contract here"
)]
impl VaultApi for VaultClient {
    fn read_secret_engines(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<EngineInfo>, VaultError>> + Send {
        async move {
            let mounts =
                Self::with_timeout(vaultrs::sys::mount::list(&self.inner), "sys/mounts").await;
            match mounts {
                Ok(mounts) => {
                    // `vaultrs` decodes the whole mount record, so the type, KV
                    // version (`options.version`), accessor and lease TTLs come
                    // along for free — the engines view needs them to tell KV2
                    // apart from `cubbyhole`/`transit`/`sys`.
                    let mut entries = mounts
                        .into_iter()
                        .map(|(name, mount)| EngineInfo {
                            name: SecretPath::new(strip_trailing_slash(&name)),
                            mount_type: mount.mount_type,
                            kv_version: mount
                                .options
                                .as_ref()
                                .and_then(|options| options.get("version"))
                                .and_then(|version| version.parse::<u64>().ok()),
                            accessor: mount.accessor,
                            description: mount.description,
                            default_lease_ttl: mount.config.default_lease_ttl,
                            max_lease_ttl: mount.config.max_lease_ttl,
                        })
                        .collect::<Vec<_>>();
                    entries.sort_by(|left, right| left.name.cmp(&right.name));
                    Ok(entries)
                }
                Err(VaultError::Api {
                    status: 403 | 404, ..
                }) => Ok(Vec::new()),
                Err(err) => Err(err),
            }
        }
    }

    fn list_kv_secrets(
        &self,
        mount: &SecretPath,
        path: &SecretPath,
    ) -> impl std::future::Future<Output = Result<Vec<SecretEntry>, VaultError>> + Send {
        // Raw LIST with a GET ?list=true fallback: some production gateways
        // reject the LIST verb (observed 400 over HTTP/1.1); Vault and OpenBao
        // both accept GET {path}?list=true instead. Kept lenient for OpenBao
        // response variants (Vault clients must tolerate missing fields).
        let url = format!(
            "{}/v1/{}/metadata/{}",
            self.addr,
            mount.as_str(),
            path.as_str()
        );
        let api_path = format!("{}/metadata/{}", mount.as_str(), path.as_str());
        let http = self.http.clone();
        let token = self.token.expose_secret().to_owned();
        async move {
            let method = reqwest::Method::from_bytes(b"LIST")
                .map_err(|err| VaultError::Connection(err.to_string()))?;
            let body = match Self::raw_json(http.clone(), &url, method, &token, &api_path).await {
                Ok(body) => body,
                Err(VaultError::Api {
                    status: 400 | 403 | 405,
                    ..
                }) => {
                    let fallback_url = format!("{url}?list=true");
                    Self::raw_json(http, &fallback_url, reqwest::Method::GET, &token, &api_path)
                        .await?
                }
                Err(err) => return Err(err),
            };
            Ok(list_keys_from_body(&body))
        }
    }

    fn read_kv_secret(
        &self,
        mount: &SecretPath,
        path: &SecretPath,
    ) -> impl std::future::Future<Output = Result<KvData, VaultError>> + Send {
        // Raw GET (not vaultrs typed reads): the metadata block of a KV2 response
        // carries fields Vault/OpenBao variants may emit as `null` or omit.
        // Rust's strict serde rejects `null` for `String` while Go's json decoder
        // tolerates it — parity requires the same leniency here.
        let url = format!("{}/v1/{}/data/{}", self.addr, mount.as_str(), path.as_str());
        let http = self.http.clone();
        let token = self.token.expose_secret().to_owned();
        async move {
            let body = Self::raw_json(http, &url, reqwest::Method::GET, &token, &url).await?;
            kv_data_from_value(body.get("data").unwrap_or(&Value::Null))
        }
    }

    fn read_kv_metadata(
        &self,
        mount: &SecretPath,
        path: &SecretPath,
    ) -> impl std::future::Future<Output = Result<KvVersionHistory, VaultError>> + Send {
        let url = format!(
            "{}/v1/{}/metadata/{}",
            self.addr,
            mount.as_str(),
            path.as_str()
        );
        let api_path = format!("{}/metadata/{}", mount.as_str(), path.as_str());
        let http = self.http.clone();
        let token = self.token.expose_secret().to_owned();
        async move {
            let body = Self::raw_json(http, &url, reqwest::Method::GET, &token, &api_path).await?;
            let data = body.get("data").and_then(Value::as_object).ok_or_else(|| {
                VaultError::Parse("metadata response had no object data field".to_owned())
            })?;
            let current_version = data
                .get("current_version")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let mut versions = data.get("versions").and_then(Value::as_object).map_or_else(
                Vec::new,
                |version_map| {
                    version_map
                        .iter()
                        .filter_map(|(version_key, metadata)| {
                            version_key.parse::<u64>().ok().map(|version| {
                                let created_time = metadata
                                    .get("created_time")
                                    .and_then(Value::as_str)
                                    .unwrap_or_default()
                                    .to_owned();
                                let deletion_time = deletion_time_from_field(
                                    metadata.get("deletion_time").unwrap_or(&Value::Null),
                                );
                                let destroyed = metadata
                                    .get("destroyed")
                                    .and_then(Value::as_bool)
                                    .unwrap_or(false);
                                VersionMeta {
                                    version,
                                    created_time,
                                    deletion_time,
                                    destroyed,
                                    is_current: version == current_version,
                                }
                            })
                        })
                        .collect()
                },
            );
            versions.sort_by_key(|left| std::cmp::Reverse(left.version));
            Ok(KvVersionHistory {
                current_version,
                versions,
            })
        }
    }

    fn read_kv_version(
        &self,
        mount: &SecretPath,
        path: &SecretPath,
        version: u64,
    ) -> impl std::future::Future<Output = Result<KvData, VaultError>> + Send {
        let url = format!(
            "{}/v1/{}/data/{}?version={version}",
            self.addr,
            mount.as_str(),
            path.as_str()
        );
        let api_path = format!("{}/data/{}", mount.as_str(), path.as_str());
        let http = self.http.clone();
        let token = self.token.expose_secret().to_owned();
        async move {
            let body = Self::raw_json(http, &url, reqwest::Method::GET, &token, &api_path).await?;
            kv_data_from_value(body.get("data").unwrap_or(&Value::Null))
        }
    }

    fn write_kv_secret(
        &self,
        mount: &SecretPath,
        path: &SecretPath,
        data: &BTreeMap<String, String>,
    ) -> impl std::future::Future<Output = Result<(), VaultError>> + Send {
        async move {
            let endpoint = format!("{}/data/{}", mount.as_str(), path.as_str());
            Self::with_timeout(
                vaultrs::kv2::set(&self.inner, mount.as_str(), path.as_str(), data),
                &endpoint,
            )
            .await
            .map(|_| ())
        }
    }

    fn read_token_info(
        &self,
    ) -> impl std::future::Future<Output = Result<TokenInfo, VaultError>> + Send {
        async move {
            let response = Self::with_timeout(
                vaultrs::token::lookup_self(&self.inner),
                "auth/token/lookup-self",
            )
            .await?;
            Ok(TokenInfo {
                policies: response.policies,
                expire_time: response.expire_time,
                accessor: response.accessor,
                display_name: response.display_name,
                ttl: response.ttl,
                creation_time: response.creation_time,
                renewable: response.renewable.unwrap_or(false),
                num_uses: response.num_uses,
                orphan: response.orphan,
            })
        }
    }

    fn sys_health(
        &self,
    ) -> impl std::future::Future<Output = Result<HealthInfo, VaultError>> + Send {
        // Raw GET instead of vaultrs::sys::health: OpenBao omits fields vaultrs
        // requires (e.g. `performance_standby`), so its strict parse fails there.
        let url = format!("{}/v1/sys/health", self.addr);
        let token = self.token.expose_secret().to_owned();
        let http = self.http.clone();
        async move {
            let response = tokio::time::timeout(
                REQUEST_TIMEOUT,
                http.get(&url).header("X-Vault-Token", token).send(),
            )
            .await
            .map_err(|_| VaultError::Connection("timed out".to_owned()))?
            .map_err(|err| VaultError::Connection(err.to_string()))?;
            let body: Value = response
                .json()
                .await
                .map_err(|err| VaultError::Parse(err.to_string()))?;
            Ok(HealthInfo {
                sealed: body.get("sealed").and_then(Value::as_bool).unwrap_or(false),
                version: body
                    .get("version")
                    .and_then(Value::as_str)
                    .unwrap_or(NA_VALUE)
                    .to_owned(),
            })
        }
    }

    fn capabilities_self(
        &self,
        paths: &[String],
    ) -> impl std::future::Future<Output = Result<BTreeMap<String, Vec<String>>, VaultError>> + Send
    {
        let url = format!("{}/v1/sys/capabilities-self", self.addr);
        let token = self.token.expose_secret().to_owned();
        let http = self.http.clone();
        let paths = paths.to_vec();
        async move {
            let request_body = serde_json::json!({ "paths": paths });
            let body =
                Self::raw_json_post(http, &url, &token, "sys/capabilities-self", &request_body)
                    .await?;
            let data = body
                .get("data")
                .and_then(Value::as_object)
                .ok_or_else(|| VaultError::Parse("capabilities response had no data".to_owned()))?;
            Ok(data
                .iter()
                .map(|(path, caps)| {
                    let list = caps.as_array().map_or_else(Vec::new, |caps| {
                        caps.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    });
                    (path.clone(), list)
                })
                .collect())
        }
    }

    fn delete_kv_secret_metadata(
        &self,
        mount: &SecretPath,
        path: &SecretPath,
    ) -> impl std::future::Future<Output = Result<(), VaultError>> + Send {
        let url = format!(
            "{}/v1/{}/metadata/{}",
            self.addr,
            mount.as_str(),
            path.as_str()
        );
        let api_path = format!("{}/metadata/{}", mount.as_str(), path.as_str());
        let token = self.token.expose_secret().to_owned();
        let http = self.http.clone();
        async move {
            Self::raw_json(http, &url, reqwest::Method::DELETE, &token, &api_path)
                .await
                .map(|_| ())
        }
    }

    fn delete_kv_secret_version(
        &self,
        mount: &SecretPath,
        path: &SecretPath,
        version: u64,
    ) -> impl std::future::Future<Output = Result<(), VaultError>> + Send {
        let url = format!(
            "{}/v1/{}/delete/{}",
            self.addr,
            mount.as_str(),
            path.as_str()
        );
        let api_path = format!("{}/delete/{}", mount.as_str(), path.as_str());
        let token = self.token.expose_secret().to_owned();
        let http = self.http.clone();
        async move {
            let body = serde_json::json!({"versions": [version]});
            Self::raw_json_body(http, &url, reqwest::Method::POST, &token, &api_path, &body)
                .await
                .map(|_| ())
        }
    }

    fn undelete_kv_secret_version(
        &self,
        mount: &SecretPath,
        path: &SecretPath,
        version: u64,
    ) -> impl std::future::Future<Output = Result<(), VaultError>> + Send {
        let url = format!(
            "{}/v1/{}/undelete/{}",
            self.addr,
            mount.as_str(),
            path.as_str()
        );
        let api_path = format!("{}/undelete/{}", mount.as_str(), path.as_str());
        let token = self.token.expose_secret().to_owned();
        let http = self.http.clone();
        async move {
            let body = serde_json::json!({"versions": [version]});
            Self::raw_json_body(http, &url, reqwest::Method::POST, &token, &api_path, &body)
                .await
                .map(|_| ())
        }
    }

    fn destroy_kv_secret_version(
        &self,
        mount: &SecretPath,
        path: &SecretPath,
        version: u64,
    ) -> impl std::future::Future<Output = Result<(), VaultError>> + Send {
        let url = format!(
            "{}/v1/{}/destroy/{}",
            self.addr,
            mount.as_str(),
            path.as_str()
        );
        let api_path = format!("{}/destroy/{}", mount.as_str(), path.as_str());
        let token = self.token.expose_secret().to_owned();
        let http = self.http.clone();
        async move {
            let body = serde_json::json!({"versions": [version]});
            Self::raw_json_body(http, &url, reqwest::Method::PUT, &token, &api_path, &body)
                .await
                .map(|_| ())
        }
    }
    fn renew_token_self(&self) -> impl std::future::Future<Output = Result<(), VaultError>> + Send {
        let url = format!("{}/v1/auth/token/renew-self", self.addr);
        let token = self.token.expose_secret().to_owned();
        let http = self.http.clone();
        async move {
            Self::raw_json(
                http,
                &url,
                reqwest::Method::POST,
                &token,
                "auth/token/renew-self",
            )
            .await
            .map(|_| ())
        }
    }

    fn list_acl_policies(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<PolicyEntry>, VaultError>> + Send {
        let url = format!("{}/v1/sys/policies/acl", self.addr);
        let api_path = "sys/policies/acl".to_owned();
        let http = self.http.clone();
        let token = self.token.expose_secret().to_owned();
        async move {
            let method = reqwest::Method::from_bytes(b"LIST")
                .map_err(|err| VaultError::Connection(err.to_string()))?;
            let body = match Self::raw_json(http.clone(), &url, method, &token, &api_path).await {
                Ok(body) => body,
                Err(VaultError::Api {
                    status: 400 | 403 | 405,
                    ..
                }) => {
                    let fallback_url = format!("{url}?list=true");
                    Self::raw_json(http, &fallback_url, reqwest::Method::GET, &token, &api_path)
                        .await?
                }
                Err(err) => return Err(err),
            };
            let mut entries: Vec<PolicyEntry> = body
                .get("data")
                .and_then(|data| data.get("keys"))
                .and_then(Value::as_array)
                .map_or_else(Vec::new, |keys| {
                    keys.iter()
                        .filter_map(Value::as_str)
                        .map(|name| PolicyEntry {
                            name: name.to_owned(),
                        })
                        .collect()
                });
            entries.sort_by(|left, right| left.name.cmp(&right.name));
            Ok(entries)
        }
    }

    fn read_acl_policy(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<PolicyDocument, VaultError>> + Send {
        let encoded_name = encode_acl_policy_name(name);
        let url = format!("{}/v1/sys/policies/acl/{encoded_name}", self.addr);
        let api_path = format!("sys/policies/acl/{encoded_name}");
        let requested_name = name.to_owned();
        let http = self.http.clone();
        let token = self.token.expose_secret().to_owned();
        async move {
            let body = Self::raw_json(http, &url, reqwest::Method::GET, &token, &api_path).await?;
            let data = body
                .get("data")
                .ok_or_else(|| VaultError::Parse("policy response had no data".to_owned()))?;
            let resolved_name = data
                .get("name")
                .and_then(Value::as_str)
                .map_or_else(|| requested_name.clone(), str::to_owned);
            let raw_policy = data
                .get("policy")
                .and_then(Value::as_str)
                .ok_or_else(|| VaultError::Parse("policy response had no policy".to_owned()))?;
            Ok(PolicyDocument {
                name: resolved_name,
                policy: decode_acl_policy_body(raw_policy)?,
            })
        }
    }

    fn write_acl_policy(
        &self,
        name: &str,
        policy: &str,
    ) -> impl std::future::Future<Output = Result<(), VaultError>> + Send {
        let encoded_name = encode_acl_policy_name(name);
        let url = format!("{}/v1/sys/policies/acl/{encoded_name}", self.addr);
        let api_path = format!("sys/policies/acl/{encoded_name}");
        let body = serde_json::json!({"policy": policy});
        let token = self.token.expose_secret().to_owned();
        let http = self.http.clone();
        async move {
            Self::raw_request(
                http.put(url).header("X-Vault-Token", token).json(&body),
                &api_path,
            )
            .await
            .map(|_| ())
        }
    }

    fn create_token(
        &self,
        request: &TokenCreateRequest,
    ) -> impl std::future::Future<Output = Result<MintedToken, VaultError>> + Send {
        let url = format!("{}/v1/auth/token/create", self.addr);
        let token = self.token.expose_secret().to_owned();
        let http = self.http.clone();
        let body = token_create_body(request);
        async move {
            let response =
                Self::raw_json_post(http, &url, &token, "auth/token/create", &body).await?;
            minted_token_from_body(&response)
        }
    }

    fn wrap_data(
        &self,
        data: &Value,
        ttl: Option<&str>,
    ) -> impl std::future::Future<Output = Result<WrappedToken, VaultError>> + Send {
        let url = format!("{}/v1/sys/wrapping/wrap", self.addr);
        let token = self.token.expose_secret().to_owned();
        let http = self.http.clone();
        let data = data.clone();
        let ttl = ttl.unwrap_or(DEFAULT_WRAP_TTL).to_owned();
        async move {
            // The wrap TTL travels as a header, not in the body, and is required.
            let request = http
                .post(&url)
                .header("X-Vault-Token", &token)
                .header("X-Vault-Wrap-TTL", ttl.as_str())
                .json(&data);
            let response = Self::raw_request(request, "sys/wrapping/wrap").await?;
            wrapped_token_from_body(&response)
        }
    }

    fn unwrap_data(
        &self,
        wrapping_token: &str,
    ) -> impl std::future::Future<Output = Result<String, VaultError>> + Send {
        let url = format!("{}/v1/sys/wrapping/unwrap", self.addr);
        let http = self.http.clone();
        let wrapping_token = wrapping_token.to_owned();
        async move {
            // The wrapping token authenticates the unwrap request itself.
            let response = Self::raw_json(
                http,
                &url,
                reqwest::Method::POST,
                &wrapping_token,
                "sys/wrapping/unwrap",
            )
            .await?;
            serde_json::to_string_pretty(&unwrap_payload(&response))
                .map_err(|err| VaultError::Parse(err.to_string()))
        }
    }
}

/// Builds the `auth/token/create` request body, omitting unset parameters so
/// Vault applies its defaults.
fn token_create_body(request: &TokenCreateRequest) -> Value {
    let mut body = serde_json::Map::new();
    if !request.policies.is_empty() {
        body.insert("policies".to_owned(), Value::from(request.policies.clone()));
    }
    if let Some(ttl) = &request.ttl {
        body.insert("ttl".to_owned(), Value::from(ttl.clone()));
    }
    if let Some(num_uses) = request.num_uses {
        body.insert("num_uses".to_owned(), Value::from(num_uses));
    }
    Value::Object(body)
}

fn minted_token_from_body(response: &Value) -> Result<MintedToken, VaultError> {
    let auth = response
        .get("auth")
        .ok_or_else(|| VaultError::Parse("create-token response had no auth block".to_owned()))?;
    let token = auth
        .get("client_token")
        .and_then(Value::as_str)
        .ok_or_else(|| VaultError::Parse("create-token response had no client_token".to_owned()))?;
    let mut policies = string_list(auth, "token_policies");
    if policies.is_empty() {
        policies = string_list(auth, "policies");
    }
    Ok(MintedToken {
        token: SecretString::from(token.to_owned()),
        accessor: string_field(auth, "accessor"),
        policies,
        ttl: auth.get("lease_duration").and_then(Value::as_u64),
        renewable: auth
            .get("renewable")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

fn wrapped_token_from_body(response: &Value) -> Result<WrappedToken, VaultError> {
    let info = response
        .get("wrap_info")
        .ok_or_else(|| VaultError::Parse("wrap response had no wrap_info".to_owned()))?;
    let token = info
        .get("token")
        .and_then(Value::as_str)
        .ok_or_else(|| VaultError::Parse("wrap response had no token".to_owned()))?;
    Ok(WrappedToken {
        token: SecretString::from(token.to_owned()),
        accessor: string_field(info, "accessor"),
        ttl: info.get("ttl").and_then(Value::as_u64).unwrap_or(0),
    })
}

/// Returns the unwrapped payload: the `data` block when present, else the envelope.
fn unwrap_payload(response: &Value) -> Value {
    response
        .get("data")
        .cloned()
        .unwrap_or_else(|| response.clone())
}

fn string_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn string_list(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or_else(Vec::new, |items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
}

fn secret_entry(key: &str) -> SecretEntry {
    if key.ends_with('/') {
        SecretEntry::dir(key)
    } else {
        SecretEntry::leaf(key)
    }
}

/// Extracts directory/leaf entries from the `data.keys` array of a list response.
fn list_keys_from_body(body: &Value) -> Vec<SecretEntry> {
    body.get("data")
        .and_then(|data| data.get("keys"))
        .and_then(Value::as_array)
        .map_or_else(Vec::new, |keys| {
            keys.iter()
                .filter_map(Value::as_str)
                .map(secret_entry)
                .collect()
        })
}

fn strip_trailing_slash(name: &str) -> &str {
    name.strip_suffix('/').map_or(name, |stripped| stripped)
}

fn kv_data_from_value(data_block: &Value) -> Result<KvData, VaultError> {
    let data_map = data_block
        .get("data")
        .and_then(Value::as_object)
        .ok_or_else(|| VaultError::Parse("KV2 data field was not an object".to_owned()))?;
    let data = data_map
        .iter()
        .map(|(key, value)| (key.clone(), SecretString::from(display_value(value))))
        .collect();
    let metadata = data_block.get("metadata").unwrap_or(&Value::Null);
    Ok(KvData {
        data,
        metadata: KvMetadata {
            version: metadata.get("version").and_then(Value::as_u64).unwrap_or(0),
            destroyed: metadata
                .get("destroyed")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            created_time: metadata
                .get("created_time")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            deletion_time: deletion_time_from_field(
                metadata.get("deletion_time").unwrap_or(&Value::Null),
            ),
        },
    })
}

fn deletion_time_from_field(value: &Value) -> Option<String> {
    value
        .as_str()
        .filter(|timestamp| !timestamp.is_empty())
        .map(str::to_owned)
}

fn display_value(value: &Value) -> String {
    match value {
        Value::String(raw) => raw.clone(),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::Array(_) | Value::Object(_) => {
            value.to_string()
        }
    }
}

fn map_client_error(err: ClientError, path: &str) -> VaultError {
    match err {
        ClientError::APIError { code, errors } => VaultError::Api {
            status: code,
            path: path.to_owned(),
            detail: truncate_detail(&errors.join("; ")),
        },
        ClientError::JsonParseError { source } => VaultError::Parse(source.to_string()),
        ClientError::ResponseEmptyError
        | ClientError::ResponseDataEmptyError
        | ClientError::ResponseWrapError
        | ClientError::InvalidUpdateParameter => VaultError::Parse(err.to_string()),
        ClientError::RestClientError { source } => VaultError::Connection(source.to_string()),
        ClientError::FileNotFoundError { path: file }
        | ClientError::FileReadError { path: file, .. }
        | ClientError::FileWriteError { path: file, .. }
        | ClientError::ParseCertificateError { path: file, .. } => {
            VaultError::Connection(format!("vault client file error at {file}"))
        }
        ClientError::InvalidLoginMethodError
        | ClientError::RestClientBuildError { .. }
        | ClientError::WrapInvalidError => VaultError::Connection(err.to_string()),
    }
}

fn truncate_detail(detail: &str) -> String {
    let mut output = String::new();
    for ch in detail.chars().take(ERROR_DETAIL_LIMIT) {
        output.push(ch);
    }
    output.replace(['\n', '\r'], " ")
}

/// Extracts the first `errors[0]` entry from a Vault error envelope.
fn error_detail_from_body(body: &Value) -> String {
    body.get("errors")
        .and_then(Value::as_array)
        .and_then(|errors| errors.first())
        .and_then(Value::as_str)
        .map_or_else(String::new, truncate_detail)
}

fn decode_acl_policy_body(policy: &str) -> Result<String, VaultError> {
    if let Some(payload) = policy.strip_prefix("base64:") {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .map_err(|err| VaultError::Parse(err.to_string()))?;
        String::from_utf8(bytes).map_err(|err| VaultError::Parse(err.to_string()))
    } else {
        Ok(policy.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_acl_policy_body, encode_acl_policy_name};

    #[test]
    fn decode_acl_policy_base64_prefix_decodes_utf8() {
        let decoded = decode_acl_policy_body("base64:cGF0aCBcInNlY3JldC9cIiB7fQ==")
            .expect("base64 policy should decode");
        assert_eq!(decoded, "path \\\"secret/\\\" {}");
    }

    #[test]
    fn encode_acl_policy_name_escapes_slashes() {
        let encoded = encode_acl_policy_name("team/admin");
        assert_eq!(encoded, "team%2Fadmin");
    }
}
