//! API keys, kept in the Windows Credential Manager (generic credentials named `Vigil/<id>`, saved
//! for this user on this computer), never in `settings.json`. Environment variables still work as a
//! fallback (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `VT_API_KEY`).
//!
//! One key per API standard: the OpenAI-compatible and the Anthropic-compatible endpoint the user
//! configured, plus VirusTotal.
//!
//! The UI only ever learns whether a key is stored; values never leave Rust.

use std::collections::HashMap;
#[cfg(test)]
use std::sync::Mutex;

/// The secrets Vigil knows.
pub const SECRET_IDS: [&str; 3] = ["openai-compatible", "anthropic-compatible", "virustotal"];

/// Longest key accepted (Credential Manager blobs are limited to 2560 bytes).
const MAX_SECRET_LEN: usize = 512;

/// Where keys are kept. The app uses [`CredentialStore`]; tests use an in-memory store.
pub trait SecretStore: Send + Sync {
    fn get(&self, id: &str) -> Option<String>;
    fn set(&self, id: &str, value: &str) -> Result<(), String>;
    fn delete(&self, id: &str) -> Result<(), String>;
}

/// Checks a secret id and a value typed by the user: printable ASCII without spaces.
pub fn clean_secret(id: &str, value: &str) -> Result<String, String> {
    if !SECRET_IDS.contains(&id) {
        return Err(format!("unknown secret \"{id}\""));
    }
    let value = value.trim();
    if value.len() > MAX_SECRET_LEN || !value.chars().all(|c| c.is_ascii_graphic()) {
        return Err(vigil_i18n::tr!(
            "This API key is not valid: it must be a single word of letters, digits and symbols."
        ));
    }
    Ok(value.to_string())
}

/// A stored key, or the environment variable that can stand in for it.
pub fn lookup(store: &dyn SecretStore, id: &str) -> Option<String> {
    store
        .get(id)
        .filter(|v| !v.is_empty())
        .or_else(|| vigil_scan::ai::env_key(id))
}

/// Which secrets are stored (environment variables are not reported: the UI offers to store one).
pub fn stored(store: &dyn SecretStore) -> HashMap<String, bool> {
    SECRET_IDS
        .iter()
        .map(|id| (id.to_string(), store.get(id).is_some_and(|v| !v.is_empty())))
        .collect()
}

// --------------------------------------------------------------------------- in memory (tests)

/// Keys kept in memory only (tests).
#[cfg(test)]
#[derive(Default)]
pub struct MemoryStore(Mutex<HashMap<String, String>>);

#[cfg(test)]
impl SecretStore for MemoryStore {
    fn get(&self, id: &str) -> Option<String> {
        self.0.lock().ok()?.get(id).cloned()
    }

    fn set(&self, id: &str, value: &str) -> Result<(), String> {
        let value = clean_secret(id, value)?;
        self.0.lock().map_err(|e| e.to_string())?.insert(id.to_string(), value);
        Ok(())
    }

    fn delete(&self, id: &str) -> Result<(), String> {
        self.0.lock().map_err(|e| e.to_string())?.remove(id);
        Ok(())
    }
}

// --------------------------------------------------------------------------- Credential Manager

/// The Windows Credential Manager of the current user.
pub struct CredentialStore {
    prefix: String,
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self {
            prefix: "Vigil/".into(),
        }
    }
}

#[cfg(windows)]
mod windows_store {
    use super::*;
    use windows::Win32::Security::Credentials::{
        CRED_FLAGS, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredFree, CredReadW,
        CredWriteW,
    };
    use windows::core::{HSTRING, PWSTR};

    impl CredentialStore {
        fn target(&self, id: &str) -> HSTRING {
            HSTRING::from(format!("{}{id}", self.prefix))
        }
    }

    impl SecretStore for CredentialStore {
        fn get(&self, id: &str) -> Option<String> {
            if !SECRET_IDS.contains(&id) {
                return None;
            }
            let target = self.target(id);
            let mut found: *mut CREDENTIALW = std::ptr::null_mut();
            // SAFETY: `found` receives a buffer the API allocates; it is freed with CredFree below.
            unsafe { CredReadW(&target, CRED_TYPE_GENERIC, None, &mut found) }.ok()?;
            if found.is_null() {
                return None;
            }
            // SAFETY: on success `found` points to a valid CREDENTIALW whose blob has
            // CredentialBlobSize bytes; both live until CredFree.
            let value = unsafe {
                let credential = &*found;
                let bytes = if credential.CredentialBlob.is_null() {
                    Vec::new()
                } else {
                    std::slice::from_raw_parts(credential.CredentialBlob, credential.CredentialBlobSize as usize)
                        .to_vec()
                };
                CredFree(found.cast());
                bytes
            };
            String::from_utf8(value).ok().filter(|v| !v.is_empty())
        }

        fn set(&self, id: &str, value: &str) -> Result<(), String> {
            let value = clean_secret(id, value)?;
            let mut target: Vec<u16> = format!("{}{id}", self.prefix).encode_utf16().chain(Some(0)).collect();
            let mut user: Vec<u16> = "vigil".encode_utf16().chain(Some(0)).collect();
            let mut blob = value.into_bytes();
            let credential = CREDENTIALW {
                Flags: CRED_FLAGS(0),
                Type: CRED_TYPE_GENERIC,
                TargetName: PWSTR(target.as_mut_ptr()),
                CredentialBlobSize: blob.len() as u32,
                CredentialBlob: blob.as_mut_ptr(),
                Persist: CRED_PERSIST_LOCAL_MACHINE,
                UserName: PWSTR(user.as_mut_ptr()),
                ..Default::default()
            };
            // SAFETY: every pointer in `credential` points into a buffer that outlives the call.
            let result = unsafe { CredWriteW(&credential, 0) };
            blob.fill(0);
            result.map_err(|e| {
                vigil_i18n::tr!(
                    "The key could not be saved in the Windows Credential Manager ({0}).",
                    e.message()
                )
            })
        }

        fn delete(&self, id: &str) -> Result<(), String> {
            if !SECRET_IDS.contains(&id) {
                return Err(format!("unknown secret \"{id}\""));
            }
            let target = self.target(id);
            // SAFETY: plain call with a NUL-terminated target name.
            match unsafe { CredDeleteW(&target, CRED_TYPE_GENERIC, None) } {
                Ok(()) => Ok(()),
                // Not found: nothing to delete.
                Err(e) if e.code().0 as u32 == 0x8007_0490 => Ok(()),
                Err(e) => Err(vigil_i18n::tr!(
                    "The key could not be removed from the Windows Credential Manager ({0}).",
                    e.message()
                )),
            }
        }
    }

    #[cfg(test)]
    impl CredentialStore {
        /// A store under a scratch prefix, cleaned by the test that uses it.
        pub fn scratch() -> Self {
            Self {
                prefix: format!("VigilTests-{}/", std::process::id()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_round_trip_and_validation() {
        let store = MemoryStore::default();
        assert!(store.set("openai-compatible", "  sk-abc123  ").is_ok());
        assert_eq!(store.get("openai-compatible").as_deref(), Some("sk-abc123"));
        assert!(store.set("openai-compatible", "two words").is_err());
        for removed in ["unknown", "openai", "anthropic", "gemini"] {
            assert!(store.set(removed, "x").is_err(), "{removed}");
        }
        assert!(stored(&store)["openai-compatible"]);
        assert!(!stored(&store)["anthropic-compatible"]);
        store.delete("openai-compatible").ok();
        assert!(store.get("openai-compatible").is_none());
    }

    /// Uses the real Credential Manager under a scratch prefix and removes what it wrote.
    #[cfg(windows)]
    #[test]
    fn credential_manager_round_trip_under_a_scratch_name() {
        let store = CredentialStore::scratch();
        if store.set("virustotal", "test-value-0123").is_err() {
            return; // no credential vault in this session (service account): nothing to check
        }
        assert_eq!(store.get("virustotal").as_deref(), Some("test-value-0123"));
        assert!(store.delete("virustotal").is_ok());
        assert!(store.get("virustotal").is_none());
        assert!(store.delete("virustotal").is_ok(), "deleting twice is fine");
    }
}
