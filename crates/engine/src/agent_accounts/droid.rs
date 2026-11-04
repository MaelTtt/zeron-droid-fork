//! Factory Droid: one login, read for its plan usage and nothing else.
//!
//! Droid keeps its own sign-in (`/login` inside `droid`) and renews it itself
//! — zeron never signs in to it, switches it, refreshes it or writes it.
//! What zeron does is show the account's Standard allowance (5-hour, weekly
//! and monthly windows) the way Claude's and Codex's meters are shown:
//! `GET api.factory.ai/api/billing/limits`, the call Droid's own startup and
//! `/status` make.
//!
//! The bearer token comes from, in Droid's own order of precedence:
//!
//! 1. `$FACTORY_API_KEY` — an API key from Factory's settings; Droid itself
//!    prefers it over a login.
//! 2. The account Droid is signed in as. Its store is `auth.v2.keyring` (the
//!    key lives in the system keyring, read through libsecret's
//!    `secret-tool` on Linux) or the older `auth.v2.file` next to an
//!    `auth.v2.key` file: `iv:tag:ciphertext` in base64, AES-256-GCM over a
//!    JSON blob holding the WorkOS `access_token` and `refresh_token`. Only
//!    the access token is used, and only to call Factory's own API.
//!
//! The refresh token is never touched: WorkOS rotates it, so a second
//! client refreshing would sign Droid out. The access token lives about half
//! an hour; Droid renews it whenever it runs. Past that the probe says so
//! ("refreshes the next time droid runs") instead of calling the API, and
//! the last good meters stay up (the usual stale-while-revalidate cache).
//!
//! # Custom models on a subscription
//!
//! A custom model in `settings.json` (`customModels`) can be served from
//! the user's own Claude or ChatGPT subscription by a gateway on this
//! machine, so a turn on it moves *that* plan's meter, not Factory's. Those
//! plans are the Claude Code and Codex accounts zeron already reads from
//! their own CLIs' sessions: nothing about them is copied here. All zeron
//! adds is which plan a model spends — a model whose provider is
//! `anthropic` / `openai` and whose `baseUrl` is on this machine maps to
//! Claude Code / Codex in the snapshot's `model_plans`, and the composer
//! shows that account's usage while the model is selected. Any other custom
//! model (a local server, an API-billed endpoint) spends no plan.

use aes_gcm::aead::consts::U16;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{AesGcm, aes::Aes256};

use super::*;

pub(super) const FACTORY_API: &str = "https://api.factory.ai";
const LIMITS_PATH: &str = "/api/billing/limits";
/// Where Droid keeps the store's encryption key in the system keyring.
const KEYRING_SERVICE: &str = "Factory CLI";
const KEYRING_ACCOUNT: &str = "auth-encryption-key";
const KEYRING_TIMEOUT: Duration = Duration::from_secs(5);
/// A token this close to its expiry counts as expired: the request would
/// race it.
const TOKEN_SKEW_SECS: i64 = 30;
/// A store that could not be read (keyring locked, no `secret-tool`) is
/// tried again no sooner than this.
const READ_RETRY: Duration = Duration::from_secs(60);

/// Droid's stores use 16-byte IVs, not the common 12.
type StoreCipher = AesGcm<Aes256, U16>;

/// The account Droid is signed in as. Deliberately not `Debug`: it holds a
/// bearer token.
#[derive(Clone)]
pub(super) struct DroidLogin {
    pub(super) account_key: String,
    email: String,
    auth_kind: AgentAuthKind,
    access_token: String,
    /// The token's expiry, epoch seconds (`None`: an API key, which has none).
    expires_at: Option<i64>,
}

impl DroidLogin {
    /// The login behind `$FACTORY_API_KEY`. The key itself never becomes an
    /// identity — it is fingerprinted.
    pub(super) fn api_key(key: &str) -> Self {
        let digest = Sha256::digest(key.as_bytes());
        Self {
            account_key: format!("key-{}", &crate::repos::hex(&digest)[..12]),
            email: "Factory API key".into(),
            auth_kind: AgentAuthKind::ApiKey,
            access_token: key.to_string(),
            expires_at: None,
        }
    }

    /// The login in a decrypted store: its identity from the access token's
    /// claims (WorkOS: `sub`, `org_id`, `email`, `exp`).
    pub(super) fn from_store(creds: &serde_json::Value) -> Option<Self> {
        let access_token = str_field(creds, "access_token")?;
        let claims = jwt_claims(&access_token).unwrap_or_default();
        let claim = |name: &str| str_field(&claims, name);
        let subject = claim("sub")
            .or_else(|| claim("id"))
            .or_else(|| str_field(creds, "active_organization_id"))
            .unwrap_or_else(|| "account".into());
        // Usage is per organization: a switch of org is another account.
        let account_key = match claim("org_id") {
            Some(org) => format!("{subject}:{org}"),
            None => subject,
        };
        Some(Self {
            account_key,
            email: claim("email").unwrap_or_else(|| "Factory account".into()),
            auth_kind: AgentAuthKind::Oauth,
            access_token,
            expires_at: claims.get("exp").and_then(|exp| exp.as_i64()),
        })
    }

    /// The in-memory slot the usage cache and probes work on. It is never
    /// written to disk: zeron keeps no copy of Droid's login.
    pub(super) fn slot(&self) -> Slot {
        Slot {
            id: slot_id_for(HarnessId::Droid, &self.account_key),
            harness: HarnessId::Droid,
            account_key: self.account_key.clone(),
            profile: SlotProfile {
                email: self.email.clone(),
                display_name: None,
                organization: None,
                plan: None,
                auth_kind: self.auth_kind,
            },
            credentials: serde_json::json!({
                "access_token": self.access_token,
                "expires_at": self.expires_at,
            }),
            claude_config: None,
            saved_at: now_ms(),
            created_at: None,
            store_key: None,
        }
    }
}

/// Whether a custom model's `baseUrl` is served from this machine.
fn is_local(base_url: &str) -> bool {
    reqwest::Url::parse(base_url)
        .ok()
        .is_some_and(|url| matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")))
}

/// The agent whose plan a custom model spends: Claude Code for an Anthropic
/// -style model, Codex for an OpenAI-style one, when it is served from this
/// machine. `None` for every other custom model.
pub(super) fn model_plan(model: &serde_json::Value) -> Option<(String, HarnessId)> {
    let harness = match str_field(model, "provider")?.as_str() {
        "anthropic" => HarnessId::ClaudeCode,
        "openai" => HarnessId::Codex,
        _ => return None,
    };
    is_local(&str_field(model, "baseUrl")?).then_some(())?;
    Some((str_field(model, "id")?, harness))
}

/// The last read of Droid's stores, reused while neither file changed —
/// Droid rewrites its store when it renews the token, which is exactly when
/// a fresh read is due. Keeps the keyring lookup off every list.
pub(super) struct CachedDroidLogin {
    stamp: StoreStamp,
    read_at: Instant,
    login: Option<DroidLogin>,
}

/// (modified, length) of `auth.v2.keyring` and `auth.v2.file`; `None` = absent.
type StoreStamp = [Option<(std::time::SystemTime, u64)>; 2];

const KEYRING_STORE: &str = "auth.v2.keyring";
const FILE_STORE: &str = "auth.v2.file";
const FILE_STORE_KEY: &str = "auth.v2.key";

fn store_stamp(dir: &Path) -> StoreStamp {
    [KEYRING_STORE, FILE_STORE].map(|name| {
        let meta = std::fs::metadata(dir.join(name)).ok()?;
        Some((meta.modified().ok()?, meta.len()))
    })
}

/// `iv:tag:ciphertext` (base64 each) decrypted with `key` into Droid's
/// credential blob. `None` for a wrong key, a damaged file or another format.
pub(super) fn decrypt_store(blob: &str, key: &[u8]) -> Option<serde_json::Value> {
    let mut parts = blob.trim().split(':');
    let mut next = || BASE64.decode(parts.next()?).ok();
    let (iv, tag, mut sealed) = (next()?, next()?, next()?);
    if parts.next().is_some() || iv.len() != 16 || tag.len() != 16 {
        return None;
    }
    // The AEAD wants the tag appended to the ciphertext.
    sealed.extend_from_slice(&tag);
    let plain = StoreCipher::new_from_slice(key)
        .ok()?
        .decrypt(GenericArray::from_slice(&iv), sealed.as_slice())
        .ok()?;
    serde_json::from_slice(&plain).ok()
}

/// The key `auth.v2.keyring` is sealed with, from the system keyring.
/// Linux only (libsecret via `secret-tool`); elsewhere Droid's file store
/// and `$FACTORY_API_KEY` are what zeron can read.
async fn keyring_key() -> Option<Vec<u8>> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let mut lookup = zeron_harness::process::Command::new("secret-tool");
    lookup
        .args([
            "lookup",
            "service",
            KEYRING_SERVICE,
            "account",
            KEYRING_ACCOUNT,
        ])
        .kill_on_drop(true);
    let output = tokio::time::timeout(KEYRING_TIMEOUT, lookup.output())
        .await
        .ok()?
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let key = BASE64
        .decode(String::from_utf8_lossy(&output.stdout).trim())
        .ok()?;
    (key.len() == 32).then_some(key)
}

/// The key beside the older `auth.v2.file`.
fn file_store_key(dir: &Path) -> Option<Vec<u8>> {
    let raw = std::fs::read_to_string(dir.join(FILE_STORE_KEY)).ok()?;
    let key = BASE64.decode(raw.trim()).ok()?;
    (key.len() == 32).then_some(key)
}

impl AgentAccounts {
    /// The account Droid is signed in as, if zeron can read it.
    pub(super) async fn detect_droid(&self) -> Option<DroidLogin> {
        let config = &self.inner.config;
        if config.droid_ambient
            && let Ok(key) = std::env::var("FACTORY_API_KEY")
            && !key.trim().is_empty()
        {
            return Some(DroidLogin::api_key(key.trim()));
        }
        let stamp = store_stamp(&config.droid_home);
        if stamp.iter().all(Option::is_none) {
            return None;
        }
        if let Some(cached) = lock(&self.inner.droid_login).as_ref()
            && cached.stamp == stamp
            && (cached.login.is_some() || cached.read_at.elapsed() < READ_RETRY)
        {
            return cached.login.clone();
        }
        let login = self.read_droid_stores().await;
        *lock(&self.inner.droid_login) = Some(CachedDroidLogin {
            stamp,
            read_at: Instant::now(),
            login: login.clone(),
        });
        login
    }

    /// Both stores, each with its own key. A store left behind by an older
    /// install decrypts too but holds a long-dead token, so the login whose
    /// token lasts longest wins.
    async fn read_droid_stores(&self) -> Option<DroidLogin> {
        let config = &self.inner.config;
        let dir = &config.droid_home;
        let open = |blob: &str, key: &[u8]| {
            decrypt_store(blob, key).and_then(|creds| DroidLogin::from_store(&creds))
        };
        let mut found: Vec<DroidLogin> = Vec::new();
        if config.droid_ambient
            && let Ok(blob) = std::fs::read_to_string(dir.join(KEYRING_STORE))
            && let Some(key) = keyring_key().await
        {
            found.extend(open(&blob, &key));
        }
        if let Ok(blob) = std::fs::read_to_string(dir.join(FILE_STORE))
            && let Some(key) = file_store_key(dir)
        {
            found.extend(open(&blob, &key));
        }
        found.into_iter().max_by_key(|login| login.expires_at)
    }

    /// Which agent's plan each of Droid's custom models spends, for the
    /// ones that spend a plan other than Factory's (see [`model_plan`]).
    pub(super) fn droid_model_plans(&self) -> std::collections::BTreeMap<String, HarnessId> {
        let settings =
            read_json(&self.inner.config.droid_home.join("settings.json")).unwrap_or_default();
        settings
            .get("customModels")
            .and_then(|models| models.as_array())
            .map(|models| models.iter().filter_map(model_plan).collect())
            .unwrap_or_default()
    }

    /// One probe of Factory's limits for the slot's token.
    pub(super) async fn droid_usage(&self, slot: &Slot) -> Result<UsageSnapshot, ProbeError> {
        let token =
            str_field(&slot.credentials, "access_token").ok_or(ProbeError::NoCredentials {
                why: NoCredentials::Missing,
            })?;
        let expired = slot
            .credentials
            .get("expires_at")
            .and_then(|at| at.as_i64())
            .is_some_and(|at| at <= Utc::now().timestamp() + TOKEN_SKEW_SECS);
        if expired {
            return Err(ProbeError::NoCredentials {
                why: NoCredentials::LoginExpired,
            });
        }
        self.factory_usage(&token).await
    }

    /// One probe of Factory's limits for a Droid token.
    async fn factory_usage(&self, token: &str) -> Result<UsageSnapshot, ProbeError> {
        let body = probe_json(
            "droid",
            "limits",
            self.inner
                .http
                .get(format!("{}{LIMITS_PATH}", self.inner.endpoints.factory_api))
                .bearer_auth(token)
                .header(reqwest::header::USER_AGENT, "zeron"),
        )
        .await?;
        match zeron_proto::plan_usage::factory(&body) {
            Some(windows) => Ok(UsageSnapshot {
                windows,
                plan_label: None,
                codex_reset_credits: None,
            }),
            // Signed in, but to an account with no plan: nothing to meter.
            None if body.get("hasActiveSubscription") == Some(&serde_json::Value::Bool(false)) => {
                Err(ProbeError::NoCredentials {
                    why: NoCredentials::NoPlan,
                })
            }
            None => Err(schema_error("droid", &body)),
        }
    }
}

/// The windows still counting: one whose end has passed has started over
/// from zero, and what was last read says nothing about it.
pub(super) fn live_windows(
    windows: &[AgentUsageWindow],
    now: DateTime<Utc>,
) -> Vec<AgentUsageWindow> {
    windows
        .iter()
        .filter(|window| window.resets_at.is_none_or(|end| end > now))
        .cloned()
        .collect()
}
