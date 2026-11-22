//! Bounded operator-owned Ed25519 trust bundles. Concatenated public-key PEMs
//! allow an overlap window without changing JWTs or exact execution addresses.
use crate::{Error, Result};
use jsonwebtoken::{DecodingKey, Validation};
use serde::de::DeserializeOwned;
use std::{
    io::Read,
    path::{Path, PathBuf},
};

pub(crate) fn read_file(path: &Path, private: bool) -> Result<Vec<u8>> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if !path.is_absolute() {
        return Err(Error::InvalidContract);
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| Error::Unavailable)?;
    let meta = file.metadata().map_err(|_| Error::Unavailable)?;
    if !meta.is_file()
        || meta.permissions().mode() & if private { 0o077 } else { 0o022 } != 0
        || meta.len() > 16384
    {
        return Err(Error::InvalidContract);
    }
    let mut bytes = Vec::new();
    file.take(16385)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Unavailable)?;
    if bytes.is_empty() || bytes.len() > 16384 {
        return Err(Error::InvalidContract);
    }
    Ok(bytes)
}

#[derive(Clone)]
pub(crate) enum VerificationKeys {
    Static(Vec<DecodingKey>),
    File(PathBuf),
}
impl VerificationKeys {
    pub(crate) fn new(bytes: &[u8]) -> Result<Self> {
        Ok(Self::Static(Self::parse(bytes)?))
    }
    pub(crate) fn file(path: PathBuf) -> Result<Self> {
        Self::parse(&read_file(&path, false)?)?;
        Ok(Self::File(path))
    }
    fn parse(bytes: &[u8]) -> Result<Vec<DecodingKey>> {
        if bytes.is_empty() || bytes.len() > 16384 {
            return Err(Error::InvalidContract);
        }
        let pems = pem::parse_many(bytes).map_err(|_| Error::InvalidContract)?;
        if pems.is_empty() || pems.len() > 8 {
            return Err(Error::InvalidContract);
        }
        // Do not silently accept a truncated/partially written second key. The
        // parser allows surrounding prose, so check that the input consists only
        // of complete PEM blocks and whitespace as well.
        let input = std::str::from_utf8(bytes).map_err(|_| Error::InvalidContract)?;
        let mut remainder = input.trim();
        for _ in &pems {
            remainder = remainder
                .strip_prefix("-----BEGIN PUBLIC KEY-----")
                .ok_or(Error::InvalidContract)?;
            let (_, tail) = remainder
                .split_once("-----END PUBLIC KEY-----")
                .ok_or(Error::InvalidContract)?;
            remainder = tail.trim_start();
        }
        if !remainder.is_empty() {
            return Err(Error::InvalidContract);
        }
        let mut seen = std::collections::HashSet::new();
        pems.into_iter()
            .map(|p| {
                if p.tag() != "PUBLIC KEY" || !seen.insert(p.contents().to_vec()) {
                    return Err(Error::InvalidContract);
                }
                DecodingKey::from_ed_pem(pem::encode(&p).as_bytes())
                    .map_err(|_| Error::InvalidContract)
            })
            .collect()
    }
    pub(crate) fn decode<T: DeserializeOwned>(
        &self,
        token: &str,
        validation: &Validation,
    ) -> Result<T> {
        if token.len() > 8192 {
            return Err(Error::Unauthorized);
        }
        let keys = match self {
            Self::Static(keys) => keys.clone(),
            // No stale-key fallback on deletion, corruption or unsafe permissions.
            Self::File(path) => Self::parse(&read_file(path, false)?)?,
        };
        keys.iter()
            .find_map(|key| {
                jsonwebtoken::decode::<T>(token, key, validation)
                    .ok()
                    .map(|v| v.claims)
            })
            .ok_or(Error::Unauthorized)
    }
}
