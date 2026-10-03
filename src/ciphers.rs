//! Parsing of OpenSSL cipher strings, TLS1.3 ciphersuite lists and group lists.
//!
//! This is a subset of OpenSSL's cipher string language, evaluated against the
//! (small) set of cipher suites that rustls supports.  Aliases naming algorithms
//! rustls does not implement simply match nothing, as OpenSSL does for aliases
//! that select no ciphers.

use core::ffi::c_int;
use core::ptr;

use openssl_sys::{
    stack_st_SSL_CIPHER, OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_push, OPENSSL_STACK,
};
use rustls::crypto::{aws_lc_rs as provider, SupportedKxGroup};
use rustls::NamedGroup;

use crate::constants::{named_group_to_nid, NID_AUTH_ECDSA, NID_AUTH_RSA};
use crate::SslCipher;

/// All supported TLS1.2 cipher suites, in OpenSSL's default preference order.
static TLS12_CIPHERS: &[&SslCipher] = &[
    &crate::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    &crate::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    &crate::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    &crate::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    &crate::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    &crate::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
];

/// All supported TLS1.3 cipher suites, in OpenSSL's default preference order.
static TLS13_CIPHERS: &[&SslCipher] = &[
    &crate::TLS13_AES_256_GCM_SHA384,
    &crate::TLS13_CHACHA20_POLY1305_SHA256,
    &crate::TLS13_AES_128_GCM_SHA256,
];

/// The configured cipher suites of an `SSL_CTX` or `SSL`.
pub struct CipherConfig {
    tls13: Vec<&'static SslCipher>,
    tls12: Vec<&'static SslCipher>,
    /// Lazily-built `STACK_OF(SSL_CIPHER)` for `SSL_get_ciphers`.
    stack: Option<CipherStack>,
}

impl Clone for CipherConfig {
    fn clone(&self) -> Self {
        Self {
            tls13: self.tls13.clone(),
            tls12: self.tls12.clone(),
            stack: None,
        }
    }
}

impl Default for CipherConfig {
    fn default() -> Self {
        Self {
            tls13: TLS13_CIPHERS.to_vec(),
            tls12: TLS12_CIPHERS.to_vec(),
            stack: None,
        }
    }
}

impl CipherConfig {
    /// `SSL_CTX_set_cipher_list`: configures the TLS1.2 cipher suites.
    pub fn set_cipher_list(&mut self, spec: &str) -> bool {
        match parse_cipher_list(spec) {
            Some(list) => {
                self.tls12 = list;
                self.stack = None;
                true
            }
            None => false,
        }
    }

    /// `SSL_CTX_set_ciphersuites`: configures the TLS1.3 cipher suites.
    pub fn set_ciphersuites(&mut self, spec: &str) -> bool {
        match parse_ciphersuites(spec) {
            Some(list) => {
                self.tls13 = list;
                self.stack = None;
                true
            }
            None => false,
        }
    }

    /// All enabled cipher suites, TLS1.3 first, in preference order.
    pub fn iter(&self) -> impl Iterator<Item = &'static SslCipher> + '_ {
        self.tls13.iter().chain(self.tls12.iter()).copied()
    }

    pub fn rustls_suites(&self) -> Vec<rustls::SupportedCipherSuite> {
        self.iter().map(|c| *c.rustls).collect()
    }

    pub fn as_stack(&mut self) -> *mut stack_st_SSL_CIPHER {
        if self.stack.is_none() {
            self.stack = CipherStack::new(self.iter());
        }
        self.stack
            .as_ref()
            .map(|s| s.raw)
            .unwrap_or_else(ptr::null_mut)
    }
}

/// An owned `STACK_OF(SSL_CIPHER)` holding `'static` `SSL_CIPHER` pointers.
struct CipherStack {
    raw: *mut stack_st_SSL_CIPHER,
}

impl CipherStack {
    fn new<'a>(ciphers: impl Iterator<Item = &'a SslCipher>) -> Option<Self> {
        let raw = unsafe { OPENSSL_sk_new_null() };
        if raw.is_null() {
            return None;
        }
        let stack = Self {
            raw: raw as *mut stack_st_SSL_CIPHER,
        };
        for c in ciphers {
            if unsafe { OPENSSL_sk_push(raw, c as *const SslCipher as *const _) } <= 0 {
                return None;
            }
        }
        Some(stack)
    }
}

impl Drop for CipherStack {
    fn drop(&mut self) {
        unsafe { OPENSSL_sk_free(self.raw as *mut OPENSSL_STACK) };
    }
}

/// Does `cipher` match the single OpenSSL cipher alias `alias`?
fn alias_matches(alias: &str, cipher: &SslCipher) -> bool {
    let name = cipher.openssl_name.to_str().unwrap_or_default();
    if alias == name || cipher.standard_name.to_bytes() == alias.as_bytes() {
        return true;
    }

    match alias {
        "ALL" | "DEFAULT" | "HIGH" | "ECDHE" | "EECDH" | "kECDHE" | "kEECDH" | "AEAD"
        | "TLSv1.2" | "FIPS" => true,
        "aECDSA" | "ECDSA" => cipher.auth == NID_AUTH_ECDSA,
        "aRSA" => cipher.auth == NID_AUTH_RSA,
        "AES" => name.contains("-AES"),
        "AESGCM" => name.contains("-GCM-"),
        "AES128" => name.contains("-AES128-"),
        "AES256" => name.contains("-AES256-"),
        "CHACHA20" => name.contains("-CHACHA20-"),
        // nb. `SHA256`/`SHA384` select by MAC, and so match no AEAD suites.
        // everything else either names an algorithm we don't support (and so
        // selects nothing, as in OpenSSL) or is unknown (and ignored, as in OpenSSL)
        _ => false,
    }
}

/// Does `cipher` match `a+b+c` (the intersection of each alias)?
fn item_matches(item: &str, cipher: &SslCipher) -> bool {
    item.split('+').all(|alias| alias_matches(alias, cipher))
}

/// Evaluate an OpenSSL cipher string against the supported TLS1.2 suites.
///
/// Returns `None` if no cipher suites were selected (which OpenSSL reports as
/// an error).
pub fn parse_cipher_list(spec: &str) -> Option<Vec<&'static SslCipher>> {
    let mut list: Vec<&'static SslCipher> = vec![];
    let mut banned: Vec<&'static SslCipher> = vec![];

    for token in spec.split([':', ',', ' ', ';']).filter(|t| !t.is_empty()) {
        if token == "@STRENGTH" {
            // stable sort, so equal-strength suites keep their order
            list.sort_by_key(|c| core::cmp::Reverse(c.bits));
            continue;
        }
        if token.starts_with('@') {
            // eg `@SECLEVEL=n`: not applicable
            continue;
        }

        let (op, item) = match token.as_bytes()[0] {
            op @ (b'!' | b'-' | b'+') => (op, &token[1..]),
            _ => (b' ', token),
        };

        let matches = TLS12_CIPHERS
            .iter()
            .copied()
            .filter(|c| item_matches(item, c));

        match op {
            b'!' => {
                for c in matches {
                    list.retain(|l| !ptr::eq(*l, c));
                    banned.push(c);
                }
            }
            b'-' => {
                for c in matches {
                    list.retain(|l| !ptr::eq(*l, c));
                }
            }
            b'+' => {
                for c in matches {
                    if list.iter().any(|l| ptr::eq(*l, c)) {
                        list.retain(|l| !ptr::eq(*l, c));
                        list.push(c);
                    }
                }
            }
            _ => {
                for c in matches {
                    if !list.iter().any(|l| ptr::eq(*l, c))
                        && !banned.iter().any(|b| ptr::eq(*b, c))
                    {
                        list.push(c);
                    }
                }
            }
        }
    }

    match list.is_empty() {
        true => None,
        false => Some(list),
    }
}

/// Parse a TLS1.3 ciphersuite list (`SSL_CTX_set_ciphersuites`).
///
/// An empty string disables all TLS1.3 suites.  Unknown names are an error,
/// as in OpenSSL.
pub fn parse_ciphersuites(spec: &str) -> Option<Vec<&'static SslCipher>> {
    let mut list: Vec<&'static SslCipher> = vec![];
    for name in spec.split(':').filter(|t| !t.is_empty()) {
        let cipher = TLS13_CIPHERS
            .iter()
            .copied()
            .find(|c| c.openssl_name.to_bytes() == name.as_bytes())?;
        if !list.iter().any(|l| ptr::eq(*l, cipher)) {
            list.push(cipher);
        }
    }
    Some(list)
}

fn group_by_name(name: &str) -> Option<NamedGroup> {
    Some(match name.to_ascii_lowercase().as_str() {
        "x25519" => NamedGroup::X25519,
        "x448" => NamedGroup::X448,
        "p-256" | "prime256v1" | "secp256r1" => NamedGroup::secp256r1,
        "p-384" | "secp384r1" => NamedGroup::secp384r1,
        "p-521" | "secp521r1" => NamedGroup::secp521r1,
        "x25519mlkem768" => NamedGroup::X25519MLKEM768,
        "secp256r1mlkem768" => NamedGroup::secp256r1MLKEM768,
        "mlkem512" => NamedGroup::MLKEM512,
        "mlkem768" => NamedGroup::MLKEM768,
        "mlkem1024" => NamedGroup::MLKEM1024,
        "ffdhe2048" => NamedGroup::FFDHE2048,
        "ffdhe3072" => NamedGroup::FFDHE3072,
        "ffdhe4096" => NamedGroup::FFDHE4096,
        "ffdhe6144" => NamedGroup::FFDHE6144,
        "ffdhe8192" => NamedGroup::FFDHE8192,
        _ => return None,
    })
}

fn supported_group(group: NamedGroup) -> Option<&'static dyn SupportedKxGroup> {
    provider::ALL_KX_GROUPS
        .iter()
        .copied()
        .find(|g| g.name() == group)
}

/// Parse an OpenSSL group list (`SSL_CTX_set1_groups_list`).
///
/// Supports the OpenSSL 3.5 syntax only to the extent of ignoring
/// key share (`*`) and tuple (`/`) markers.  Groups that are known
/// but not supported by rustls are skipped, as are unknown groups
/// prefixed with `?`.
pub fn parse_groups_list(spec: &str) -> Option<Vec<&'static dyn SupportedKxGroup>> {
    let mut list: Vec<&'static dyn SupportedKxGroup> = vec![];
    for token in spec.split([':', '/']).filter(|t| !t.is_empty()) {
        let token = token.trim_start_matches(['*', '?']);
        if token == "DEFAULT" {
            for g in provider::default_provider().kx_groups {
                if !list.iter().any(|l| l.name() == g.name()) {
                    list.push(g);
                }
            }
            continue;
        }
        let Some(group) = group_by_name(token) else {
            log::warn!("ignoring unknown group {token:?}");
            continue;
        };
        if let Some(g) = supported_group(group) {
            if !list.iter().any(|l| l.name() == g.name()) {
                list.push(g);
            }
        }
    }
    match list.is_empty() {
        true => None,
        false => Some(list),
    }
}

/// Map an array of group NIDs (`SSL_CTX_set1_groups`) to supported groups.
pub fn groups_from_nids(nids: &[c_int]) -> Option<Vec<&'static dyn SupportedKxGroup>> {
    let list: Vec<_> = nids
        .iter()
        .filter_map(|nid| {
            provider::ALL_KX_GROUPS
                .iter()
                .copied()
                .find(|g| named_group_to_nid(g.name()) == Some(*nid))
        })
        .collect();
    match list.is_empty() {
        true => None,
        false => Some(list),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&SslCipher]) -> Vec<&'static str> {
        list.iter()
            .map(|c| c.openssl_name.to_str().unwrap())
            .collect()
    }

    #[test]
    fn cipher_lists() {
        assert_eq!(
            names(&parse_cipher_list("HIGH:!aNULL:!MD5").unwrap()),
            names(TLS12_CIPHERS)
        );
        assert_eq!(
            names(
                &parse_cipher_list(
                    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:BOGUS"
                )
                .unwrap()
            ),
            vec![
                "ECDHE-ECDSA-AES128-GCM-SHA256",
                "ECDHE-RSA-AES128-GCM-SHA256"
            ]
        );
        assert_eq!(
            names(&parse_cipher_list("ECDHE+AESGCM:!aRSA").unwrap()),
            vec![
                "ECDHE-ECDSA-AES256-GCM-SHA384",
                "ECDHE-ECDSA-AES128-GCM-SHA256"
            ]
        );
        assert_eq!(
            names(&parse_cipher_list("aRSA+AES128:aECDSA+AES128:+aRSA").unwrap()),
            vec![
                "ECDHE-ECDSA-AES128-GCM-SHA256",
                "ECDHE-RSA-AES128-GCM-SHA256"
            ]
        );
        assert!(parse_cipher_list("RC4:3DES").is_none());
        assert!(parse_cipher_list("ALL:!ALL").is_none());
    }

    #[test]
    fn ciphersuites() {
        assert_eq!(
            names(&parse_ciphersuites("TLS_AES_128_GCM_SHA256").unwrap()),
            vec!["TLS_AES_128_GCM_SHA256"]
        );
        assert!(parse_ciphersuites("").unwrap().is_empty());
        assert!(parse_ciphersuites("TLS_BOGUS").is_none());
    }

    #[test]
    fn groups() {
        let g = parse_groups_list("X25519:P-256:brainpoolP256r1").unwrap();
        assert_eq!(
            g.iter().map(|g| g.name()).collect::<Vec<_>>(),
            vec![NamedGroup::X25519, NamedGroup::secp256r1]
        );
        assert!(parse_groups_list("brainpoolP256r1").is_none());
    }
}
