//! Small differences between the OpenSSL 3 and AWS-LC libcrypto APIs.
//!
//! With the `awslc` feature this crate is built against an AWS-LC installation
//! and shares its libcrypto with the application, so the stack, error and
//! object helpers used elsewhere are routed through here.

use core::ffi::{c_int, c_void};

use openssl_sys::OPENSSL_STACK;

/// Number of items in `sk`, or 0 for a NULL stack.
pub unsafe fn sk_num(sk: *const OPENSSL_STACK) -> usize {
    #[cfg(not(feature = "awslc"))]
    {
        match openssl_sys::OPENSSL_sk_num(sk) {
            n if n < 0 => 0,
            n => n as usize,
        }
    }
    #[cfg(feature = "awslc")]
    {
        openssl_sys::OPENSSL_sk_num(sk)
    }
}

pub unsafe fn sk_value(sk: *const OPENSSL_STACK, index: usize) -> *mut c_void {
    #[cfg(not(feature = "awslc"))]
    {
        openssl_sys::OPENSSL_sk_value(sk, index as c_int)
    }
    #[cfg(feature = "awslc")]
    {
        openssl_sys::OPENSSL_sk_value(sk, index)
    }
}

/// Push `item`, returning false on failure.
pub unsafe fn sk_push(sk: *mut OPENSSL_STACK, item: *const c_void) -> bool {
    openssl_sys::OPENSSL_sk_push(sk, item as _) > 0
}

/// Free `sk`, calling `free` on each item.
pub unsafe fn sk_pop_free<T>(sk: *mut OPENSSL_STACK, free: unsafe extern "C" fn(*mut T)) {
    if sk.is_null() {
        return;
    }
    loop {
        let item = openssl_sys::OPENSSL_sk_pop(sk) as *mut T;
        if item.is_null() {
            break;
        }
        free(item);
    }
    openssl_sys::OPENSSL_sk_free(sk);
}

/// `X509_STORE_get1_all_certs`: a new stack holding references to all
/// certificates in the store.
pub unsafe fn x509_store_get1_all_certs(
    store: *mut openssl_sys::X509_STORE,
) -> *mut openssl_sys::stack_st_X509 {
    #[cfg(not(feature = "awslc"))]
    {
        openssl_sys::X509_STORE_get1_all_certs(store)
    }
    #[cfg(feature = "awslc")]
    {
        let objects = openssl_sys::X509_STORE_get0_objects(store) as *const OPENSSL_STACK;
        let out = openssl_sys::OPENSSL_sk_new_null();
        if out.is_null() {
            return core::ptr::null_mut();
        }
        for i in 0..sk_num(objects) {
            let obj = sk_value(objects, i) as *mut openssl_sys::X509_OBJECT;
            let cert = openssl_sys::X509_OBJECT_get0_X509(obj);
            if cert.is_null() {
                continue;
            }
            openssl_sys::X509_up_ref(cert);
            if !sk_push(out, cert as *const c_void) {
                openssl_sys::X509_free(cert);
            }
        }
        out as *mut openssl_sys::stack_st_X509
    }
}

/// Is `pkey` of the given type?
pub unsafe fn evp_pkey_is(pkey: *const openssl_sys::EVP_PKEY, kind: KeyKind) -> bool {
    #[cfg(not(feature = "awslc"))]
    {
        let name: &core::ffi::CStr = match kind {
            KeyKind::Rsa => c"RSA",
            KeyKind::RsaPss => c"RSA-PSS",
            KeyKind::Ec => c"EC",
            KeyKind::Ed25519 => c"ED25519",
            KeyKind::Ed448 => c"ED448",
        };
        EVP_PKEY_is_a(pkey, name.as_ptr()) == 1
    }
    #[cfg(feature = "awslc")]
    {
        let id = openssl_sys::EVP_PKEY_id(pkey);
        id == match kind {
            KeyKind::Rsa => openssl_sys::EVP_PKEY_RSA,
            KeyKind::RsaPss => openssl_sys::EVP_PKEY_RSA_PSS,
            KeyKind::Ec => openssl_sys::EVP_PKEY_EC,
            KeyKind::Ed25519 => openssl_sys::EVP_PKEY_ED25519,
            // not supported by AWS-LC
            KeyKind::Ed448 => return false,
        }
    }
}

#[derive(Clone, Copy)]
pub enum KeyKind {
    Rsa,
    RsaPss,
    Ec,
    Ed25519,
    Ed448,
}

/// A BIO that reads EOF and discards writes.
pub unsafe fn new_null_bio() -> *mut openssl_sys::BIO {
    #[cfg(not(feature = "awslc"))]
    {
        openssl_sys::BIO_new(BIO_s_null())
    }
    #[cfg(feature = "awslc")]
    {
        let bio = openssl_sys::BIO_new(openssl_sys::BIO_s_mem());
        if !bio.is_null() {
            openssl_sys::BIO_set_mem_eof_return(bio, 0);
        }
        bio
    }
}

/// Library code of libssl errors.
pub const ERR_LIB_SSL: c_int = if cfg!(feature = "awslc") { 16 } else { 20 };

/// Add an error to the error queue.
pub unsafe fn put_error(lib: c_int, reason: c_int, msg: &core::ffi::CStr) {
    #[cfg(not(feature = "awslc"))]
    {
        openssl_sys::ERR_new();
        // nb. miri cannot do variadic functions, so we define a miri-only equivalent
        #[cfg(not(miri))]
        openssl_sys::ERR_set_error(lib, reason, c"%s".as_ptr(), msg.as_ptr());
        #[cfg(miri)]
        crate::miri::ERR_set_error(lib, reason, msg.as_ptr());
    }
    #[cfg(feature = "awslc")]
    {
        openssl_sys::ERR_put_error(lib, 0, reason, c"rustls-libssl".as_ptr(), 0);
        openssl_sys::ERR_add_error_data(1, msg.as_ptr());
    }
}

#[cfg(not(feature = "awslc"))]
extern "C" {
    fn EVP_PKEY_is_a(pkey: *const openssl_sys::EVP_PKEY, name: *const core::ffi::c_char) -> c_int;
    fn BIO_s_null() -> *const openssl_sys::BIO_METHOD;
}
