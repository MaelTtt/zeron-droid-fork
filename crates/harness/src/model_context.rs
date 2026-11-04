//! Credential bytes are hashed locally and never included in diagnostics or disk catalogs.
use crate::{HarnessError, ModelContext};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use zeron_proto::HarnessId;

pub(crate) fn root(variable: &str, fallback: PathBuf) -> PathBuf {
    std::env::var_os(variable)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or(fallback)
}

pub(crate) fn context(
    id: HarnessId,
    binary: &Path,
    extra: &[PathBuf],
) -> Result<ModelContext, HarnessError> {
    let home = crate::executable::home_or_current_dir();
    let files = match id {
        HarnessId::Codex => vec![root("CODEX_HOME", home.join(".codex")).join("auth.json")],
        HarnessId::ClaudeCode => {
            let root = root("CLAUDE_CONFIG_DIR", home.join(".claude"));
            vec![root.join("settings.json"), root.join(".credentials.json")]
        }
        HarnessId::Cursor => vec![home.join(".cursor/sdk/auth.json")],
        HarnessId::Fx => vec![
            home.join(".fx/auth.json"),
            home.join(".fx/settings.json"),
            home.join(".fx/api-key"),
            home.join(".fx/chatgpt-auth.json"),
            home.join(".fx/grok-auth.json"),
        ],
        // The catalog follows the plan (auth), BYOK models in settings.json
        // and the org's managed settings.
        HarnessId::Droid => vec![
            home.join(".factory/auth.v2.file"),
            home.join(".factory/settings.json"),
            home.join(".factory/org-managed-settings.cache.json"),
        ],
        HarnessId::Opencode => {
            let data = root("XDG_DATA_HOME", home.join(".local/share"));
            let config = root("XDG_CONFIG_HOME", home.join(".config"));
            let cwd = std::env::current_dir()?;
            let mut files = vec![
                data.join("opencode/auth.json"),
                config.join("opencode/opencode.json"),
                config.join("opencode/opencode.jsonc"),
            ];
            for dir in cwd.ancestors() {
                for name in [
                    "opencode.json",
                    "opencode.jsonc",
                    ".opencode/opencode.json",
                    ".opencode/opencode.jsonc",
                ] {
                    files.push(dir.join(name));
                }
            }
            if let Some(path) = std::env::var_os("OPENCODE_CONFIG") {
                files.push(path.into());
            }
            files
        }
        HarnessId::Grok => {
            let root = root("GROK_HOME", home.join(".grok"));
            vec![root.join("auth.json"), root.join("config.toml")]
        }
        HarnessId::Hermes => {
            let root = root("HERMES_HOME", home.join(".hermes"));
            vec![
                root.join("auth.json"),
                root.join(".env"),
                root.join("config.yaml"),
            ]
        }
        HarnessId::Pi => {
            vec![root("PI_CODING_AGENT_DIR", home.join(".pi/agent")).join("auth.json")]
        }
        HarnessId::Devin => {
            let data = root("XDG_DATA_HOME", home.join(".local/share"));
            let mut files = vec![data.join("devin/credentials.toml")];
            if cfg!(target_os = "macos") {
                files.push(home.join("Library/Application Support/devin/credentials.toml"));
            }
            if cfg!(windows) {
                files.push(
                    root("APPDATA", home.join("AppData/Roaming")).join("devin/credentials.toml"),
                );
            }
            files
        }
        _ => vec![],
    };
    let binary = binary
        .canonicalize()
        .unwrap_or_else(|_| binary.to_path_buf());
    let version = crate::executable::binary_version(&binary).map(|v| v.to_string());
    let mut hash = Sha256::new();
    field(&mut hash, binary.as_os_str().as_encoded_bytes());
    field(
        &mut hash,
        version.as_deref().unwrap_or("unknown").as_bytes(),
    );
    // Unknown-version executables must still invalidate on replacement.
    if let Ok(metadata) = binary.metadata() {
        field(
            &mut hash,
            format!("{:?}:{}", metadata.modified().ok(), metadata.len()).as_bytes(),
        );
    }
    hash_files(&mut hash, files.iter().chain(extra))?;
    let prefixes: &[&str] = match id {
        HarnessId::Codex => &["CODEX_", "OPENAI_"],
        HarnessId::ClaudeCode => &["CLAUDE_", "ANTHROPIC_", "AWS_"],
        HarnessId::Opencode => &["OPENCODE_", "OPENAI_", "ANTHROPIC_", "GOOGLE_"],
        HarnessId::Grok => &["GROK_", "XAI_"],
        HarnessId::Hermes => &["HERMES_", "OPENAI_", "ANTHROPIC_"],
        HarnessId::Pi => &["PI_", "OPENAI_", "ANTHROPIC_"],
        HarnessId::Devin => &["DEVIN_"],
        HarnessId::Antigravity => &["GEMINI_", "GOOGLE_"],
        HarnessId::Cursor => &["CURSOR_"],
        HarnessId::Fx => &["FX_", "AI_GATEWAY_", "OPENAI_", "ANTHROPIC_"],
        // Not `FACTORY_`: a Droid-launched shell exports per-session ids
        // (`FACTORY_SESSION_ID`) that would churn the catalog on every launch.
        HarnessId::Droid => &["FACTORY_API_"],
        _ => &[],
    };
    let mut env: Vec<_> = std::env::vars_os()
        .filter(|(key, _)| {
            prefixes
                .iter()
                .any(|prefix| key.to_string_lossy().starts_with(prefix))
        })
        .collect();
    env.sort();
    for (key, value) in env {
        field(&mut hash, key.as_encoded_bytes());
        field(&mut hash, value.as_encoded_bytes());
    }
    Ok(ModelContext {
        hash: format!("{:x}", hash.finalize()),
        binary_path: binary,
        binary_version: version,
    })
}

fn field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}
/// Droid restamps `cachedAt` in its org-settings cache on every session start.
/// Hashed raw, discovery's own launch would invalidate the context it is
/// running under, so every attempt would be rejected as stale.
fn stable_bytes(path: &Path, bytes: Vec<u8>) -> Vec<u8> {
    if path
        .file_name()
        .is_some_and(|name| name == "org-managed-settings.cache.json")
        && let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&bytes)
        && let Some(object) = value.as_object_mut()
    {
        object.remove("cachedAt");
        if let Ok(stable) = serde_json::to_vec(&value) {
            return stable;
        }
    }
    bytes
}

fn hash_files<'a>(
    hash: &mut Sha256,
    files: impl Iterator<Item = &'a PathBuf>,
) -> Result<(), HarnessError> {
    for path in files {
        field(hash, path.as_os_str().as_encoded_bytes());
        match std::fs::read(path) {
            Ok(bytes) => {
                hash.update([1]);
                field(hash, &stable_bytes(path, bytes));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => hash.update([0]),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

impl ModelContext {
    pub(crate) fn key(&self) -> [u8; 32] {
        Sha256::digest(self.hash.as_bytes()).into()
    }
    pub(crate) fn log(&self) {
        tracing::info!(binary_path = %self.binary_path.display(), binary_version = self.binary_version.as_deref().unwrap_or("unknown"), "Model discovery binary");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn content_changes_and_missing_files_invalidate_without_exposing_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("auth.json");
        let key = || {
            let mut hash = Sha256::new();
            hash_files(&mut hash, std::iter::once(&file)).unwrap();
            format!("{:x}", hash.finalize())
        };
        let missing = key();
        std::fs::write(&file, "account-one").unwrap();
        let first = key();
        std::fs::write(&file, "account-two").unwrap();
        assert_ne!(first, key());
        assert_ne!(missing, first);
        assert!(!first.contains("account"));
        std::fs::remove_file(&file).unwrap();
        assert_eq!(key(), missing);
    }

    #[test]
    fn droid_org_cache_ignores_its_refresh_stamp_but_not_the_policy() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("org-managed-settings.cache.json");
        let key = || {
            let mut hash = Sha256::new();
            hash_files(&mut hash, std::iter::once(&file)).unwrap();
            format!("{:x}", hash.finalize())
        };
        let write = |blocked: &str, cached_at: u64| {
            std::fs::write(
                &file,
                format!(
                    r#"{{"orgId":"o","managedSettings":{{"modelPolicy":{{"blockedModelIds":["{blocked}"]}}}},"cachedAt":{cached_at}}}"#
                ),
            )
            .unwrap();
        };
        write("model-a", 1);
        let first = key();
        write("model-a", 2);
        assert_eq!(first, key());
        write("model-b", 2);
        assert_ne!(first, key());
        std::fs::write(&file, "not json").unwrap();
        assert_ne!(first, key());
    }
}
