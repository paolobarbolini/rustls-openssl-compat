// Entry points only present in the AWS-LC libssl ABI (`awslc` feature).
//
// Many of these are macros over `SSL_CTX_ctrl`/`SSL_ctrl` in OpenSSL but real
// functions in AWS-LC.  Included into `entry.rs`, so it shares its imports
// and the `entry!` macro.

entry! {
    pub fn _SSLv23_server_method() -> *const SSL_METHOD {
        &crate::TLS_SERVER_METHOD
    }
}

entry! {
    pub fn _SSLv23_client_method() -> *const SSL_METHOD {
        &crate::TLS_CLIENT_METHOD
    }
}

entry! {
    pub fn _SSL_get_ex_new_index(
        argl: c_long,
        argp: *mut c_void,
        _unused: *mut c_void,
        _dup_unused: *mut c_void,
        free_func: crate::ex_data::CryptoExFree,
    ) -> c_int {
        crate::ex_data::new_ssl_index(argl, argp, free_func)
    }
}

entry! {
    pub fn _SSL_CTX_get_ex_new_index(
        argl: c_long,
        argp: *mut c_void,
        _unused: *mut c_void,
        _dup_unused: *mut c_void,
        free_func: crate::ex_data::CryptoExFree,
    ) -> c_int {
        crate::ex_data::new_ssl_ctx_index(argl, argp, free_func)
    }
}

// Protocol versions: 0 means the default (lowest or highest supported).

entry! {
    pub fn _SSL_CTX_set_min_proto_version(ctx: *mut SSL_CTX, version: u16) -> c_int {
        try_clone_arc!(ctx).get_mut().set_min_protocol_version(version);
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _SSL_CTX_set_max_proto_version(ctx: *mut SSL_CTX, version: u16) -> c_int {
        try_clone_arc!(ctx).get_mut().set_max_protocol_version(version);
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _SSL_set_min_proto_version(ssl: *mut SSL, version: u16) -> c_int {
        try_clone_arc!(ssl).get_mut().set_min_protocol_version(version);
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _SSL_set_max_proto_version(ssl: *mut SSL, version: u16) -> c_int {
        try_clone_arc!(ssl).get_mut().set_max_protocol_version(version);
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _SSL_CTX_set_mode(_ctx: *mut SSL_CTX, mode: u32) -> u32 {
        // AWS-LC modes are either no-ops or behaviours rustls has by default
        // (partial writes, moving write buffers, auto retry).
        mode
    }
}

entry! {
    pub fn _SSL_CTX_set_session_cache_mode(ctx: *mut SSL_CTX, mode: c_int) -> c_int {
        if mode < 0 {
            return 0;
        }
        try_clone_arc!(ctx).get_mut().set_session_cache_mode(mode as u32) as c_int
    }
}

entry! {
    pub fn _SSL_CTX_set_session_psk_dhe_timeout(_ctx: *mut SSL_CTX, _timeout: u32) {}
}

// Certificates

entry! {
    pub fn _SSL_CTX_set1_chain(ctx: *mut SSL_CTX, chain: *mut stack_st_X509) -> c_int {
        let chain = match chain.is_null() {
            true => vec![],
            false => OwnedX509Stack::new_copy(chain).to_rustls(),
        };
        match try_clone_arc!(ctx).get_mut().stage_certificate_chain_tail(chain) {
            Ok(()) => C_INT_SUCCESS,
            Err(e) => e.raise().into(),
        }
    }
}

entry! {
    pub fn _SSL_CTX_add1_chain_cert(ctx: *mut SSL_CTX, x509: *mut X509) -> c_int {
        if x509.is_null() {
            return Error::null_pointer().raise().into();
        }
        let der = OwnedX509::new_incref(x509).der_bytes();
        match try_clone_arc!(ctx).get_mut().append_chain_cert(der.into()) {
            Ok(()) => C_INT_SUCCESS,
            Err(e) => e.raise().into(),
        }
    }
}

entry! {
    pub fn _SSL_CTX_build_cert_chain(_ctx: *mut SSL_CTX, _flags: c_int) -> c_int {
        // The chain is sent as configured.
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _SSL_get_peer_certificate(ssl: *const SSL) -> *mut X509 {
        _SSL_get1_peer_certificate(ssl)
    }
}

// Groups and signature algorithms

entry! {
    pub fn _SSL_CTX_set1_curves_list(ctx: *mut SSL_CTX, curves: *const c_char) -> c_int {
        let spec = try_str!(curves);
        match crate::ciphers::parse_groups_list(spec) {
            Some(groups) => {
                try_clone_arc!(ctx).get_mut().set_groups(groups);
                C_INT_SUCCESS
            }
            None => Error::bad_data("no supported groups").raise().into(),
        }
    }
}

entry! {
    pub fn _SSL_CTX_set1_sigalgs_list(_ctx: *mut SSL_CTX, _str: *const c_char) -> c_int {
        log::warn!("SSL_CTX_set1_sigalgs_list not implemented; using rustls defaults");
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _SSL_get_negotiated_group(ssl: *const SSL) -> c_int {
        try_clone_arc!(ssl)
            .get()
            .get_negotiated_key_exchange_group()
            .and_then(|group| named_group_to_nid(group.name()))
            .unwrap_or(NID_undef)
    }
}

// Ciphers

entry! {
    pub fn _SSL_get_cipher_by_value(value: u16) -> *const SSL_CIPHER {
        crate::SslCipher::find_by_id(rustls::CipherSuite::from(value))
            .map(|cipher| cipher as *const SSL_CIPHER)
            .unwrap_or_else(ptr::null)
    }
}

entry! {
    pub fn _SSL_CIPHER_get_cipher_nid(cipher: *const SSL_CIPHER) -> c_int {
        let name = try_ref_from_ptr!(cipher).openssl_name.to_bytes();
        let contains = |needle: &[u8]| name.windows(needle.len()).any(|w| w == needle);
        if contains(b"AES_128_GCM") || contains(b"AES128-GCM") {
            openssl_sys::NID_aes_128_gcm
        } else if contains(b"AES_256_GCM") || contains(b"AES256-GCM") {
            openssl_sys::NID_aes_256_gcm
        } else if contains(b"CHACHA20") {
            openssl_sys::NID_chacha20_poly1305
        } else {
            NID_undef
        }
    }
}

entry! {
    pub fn _SSL_CIPHER_get_handshake_digest(cipher: *const SSL_CIPHER) -> *const openssl_sys::EVP_MD {
        match try_ref_from_ptr!(cipher).openssl_name.to_bytes().ends_with(b"SHA384") {
            true => unsafe { openssl_sys::EVP_sha384() },
            false => unsafe { openssl_sys::EVP_sha256() },
        }
    }
}

// SNI and certificate selection

entry! {
    pub fn _SSL_CTX_set_tlsext_servername_callback(
        ctx: *mut SSL_CTX,
        cb: SSL_CTX_servername_callback_func,
    ) -> c_int {
        try_clone_arc!(ctx).get_mut().set_servername_callback(cb);
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _SSL_CTX_set_tlsext_servername_arg(ctx: *mut SSL_CTX, arg: *mut c_void) -> c_int {
        try_clone_arc!(ctx).get_mut().set_servername_callback_context(arg);
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _SSL_set_tlsext_host_name(ssl: *mut SSL, name: *const c_char) -> c_int {
        let hostname = try_str!(name);
        try_clone_arc!(ssl).get_mut().set_sni_hostname(hostname) as c_int
    }
}

pub type SSL_select_certificate_cb_func =
    Option<unsafe extern "C" fn(hello: *const crate::SslClientHello) -> c_int>;

entry! {
    pub fn _SSL_CTX_set_select_certificate_cb(ctx: *mut SSL_CTX, cb: SSL_select_certificate_cb_func) {
        try_clone_arc!(ctx).get_mut().set_select_certificate_cb(cb);
    }
}

entry! {
    pub fn _SSL_early_callback_ctx_extension_get(
        hello: *const crate::SslClientHello,
        extension_type: u16,
        out_data: *mut *const c_uchar,
        out_len: *mut usize,
    ) -> c_int {
        if hello.is_null() {
            return Error::null_pointer().raise().into();
        }
        let ssl = unsafe { (*hello).ssl };
        _SSL_client_hello_get0_ext(ssl, extension_type as c_uint, out_data, out_len)
    }
}

// Not supported: OCSP stapling, session ticket key callbacks, early data,
// renegotiation and the key material exports used for kTLS.

entry! {
    pub fn _SSL_CTX_set_tlsext_status_cb(_ctx: *mut SSL_CTX, _cb: *const c_void) -> c_int {
        log::warn!("OCSP stapling not implemented");
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _SSL_CTX_get_tlsext_status_cb(_ctx: *mut SSL_CTX, cb: *mut *const c_void) -> c_int {
        if !cb.is_null() {
            unsafe { *cb = ptr::null() };
        }
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _SSL_set_tlsext_status_ocsp_resp(_ssl: *mut SSL, resp: *mut u8, _resp_len: usize) -> c_int {
        // on success we own `resp`
        unsafe { openssl_sys::OPENSSL_free(resp as *mut c_void) };
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _SSL_CTX_set_tlsext_ticket_key_cb(_ctx: *mut SSL_CTX, _cb: *const c_void) -> c_int {
        log::warn!("SSL_CTX_set_tlsext_ticket_key_cb not implemented; using internal ticket keys");
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _SSL_CTX_set_early_data_enabled(_ctx: *mut SSL_CTX, _enabled: c_int) {}
}

entry! {
    pub fn _SSL_set_early_data_enabled(_ssl: *mut SSL, _enabled: c_int) {}
}

entry! {
    pub fn _SSL_in_early_data(_ssl: *const SSL) -> c_int {
        0
    }
}

entry! {
    pub fn _SSL_set_renegotiate_mode(_ssl: *mut SSL, _mode: c_int) {}
}

entry! {
    pub fn _SSL_state(ssl: *const SSL) -> c_int {
        // only SSL_ST_INIT and SSL_ST_OK are returned by AWS-LC
        const SSL_ST_OK: c_int = 0x03;
        const SSL_ST_INIT: c_int = 0x1000 | 0x2000;
        match _SSL_is_init_finished(ssl) {
            1 => SSL_ST_OK,
            _ => SSL_ST_INIT,
        }
    }
}

entry! {
    pub fn _SSL_get_key_block_len(_ssl: *const SSL) -> usize {
        0
    }
}

entry! {
    pub fn _SSL_generate_key_block(_ssl: *const SSL, _out: *mut u8, _out_len: usize) -> c_int {
        Error::not_supported("SSL_generate_key_block").raise().into()
    }
}

entry! {
    pub fn _SSL_get_read_sequence(_ssl: *const SSL) -> u64 {
        0
    }
}

entry! {
    pub fn _SSL_get_write_sequence(_ssl: *const SSL) -> u64 {
        0
    }
}

entry! {
    pub fn _SSL_get_read_traffic_secret(_ssl: *const SSL, _secret: *mut u8, _out_len: *mut usize) -> c_int {
        Error::not_supported("SSL_get_read_traffic_secret").raise().into()
    }
}

entry! {
    pub fn _SSL_get_write_traffic_secret(_ssl: *const SSL, _secret: *mut u8, _out_len: *mut usize) -> c_int {
        Error::not_supported("SSL_get_write_traffic_secret").raise().into()
    }
}
