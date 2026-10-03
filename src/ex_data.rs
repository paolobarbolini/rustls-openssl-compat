use core::ffi::{c_int, c_void};
use core::ptr;

use crate::entry::{SSL, SSL_CTX};
use crate::error::Error;

#[cfg(feature = "awslc")]
pub use awslc_impl::{new_ssl_ctx_index, new_ssl_index, CryptoExFree, ExData};
#[cfg(not(feature = "awslc"))]
pub use openssl_impl::ExData;

#[cfg(not(feature = "awslc"))]
mod openssl_impl {
    use super::*;

    /// Safe(ish), owning wrapper around an OpenSSL `CRYPTO_EX_DATA`.
    ///
    /// `ty` and `owner` allow us to drop this object with no extra context.
    ///
    /// Because this refers to the object that contains it, a two-step
    /// construction is needed.
    pub struct ExData {
        ex_data: CRYPTO_EX_DATA,
        ty: c_int,
        owner: *mut c_void,
    }

    impl ExData {
        /// Makes a new CRYPTO_EX_DATA for an SSL object.
        pub fn new_ssl(ssl: *mut SSL) -> Option<Self> {
            let mut ex_data = CRYPTO_EX_DATA::default();
            let owner = ssl as *mut c_void;
            let ty = CRYPTO_EX_INDEX_SSL;
            let rc = unsafe { CRYPTO_new_ex_data(ty, owner, &mut ex_data) };
            if rc == 1 {
                Some(Self { ex_data, ty, owner })
            } else {
                None
            }
        }

        /// Makes a new CRYPTO_EX_DATA for an SSL_CTX object.
        pub fn new_ssl_ctx(ctx: *mut SSL_CTX) -> Option<Self> {
            let mut ex_data = CRYPTO_EX_DATA::default();
            let owner = ctx as *mut c_void;
            let ty = CRYPTO_EX_INDEX_SSL_CTX;
            let rc = unsafe { CRYPTO_new_ex_data(ty, owner, &mut ex_data) };
            if rc == 1 {
                Some(Self { ex_data, ty, owner })
            } else {
                None
            }
        }

        pub fn set(&mut self, idx: c_int, data: *mut c_void) -> Result<(), Error> {
            let rc = unsafe { CRYPTO_set_ex_data(&mut self.ex_data, idx, data) };
            if rc == 1 {
                Ok(())
            } else {
                Err(Error::bad_data("CRYPTO_set_ex_data"))
            }
        }

        pub fn get(&self, idx: c_int) -> *mut c_void {
            unsafe { CRYPTO_get_ex_data(&self.ex_data, idx) }
        }
    }

    impl Drop for ExData {
        fn drop(&mut self) {
            if !self.owner.is_null() {
                unsafe {
                    CRYPTO_free_ex_data(self.ty, self.owner, &mut self.ex_data);
                };
                self.owner = ptr::null_mut();
            }
        }
    }

    impl Default for ExData {
        fn default() -> Self {
            Self {
                ex_data: CRYPTO_EX_DATA::default(),
                ty: -1,
                owner: ptr::null_mut(),
            }
        }
    }

    /// This has the same layout prefix as `struct crypto_ex_data_st` aka
    /// `CRYPTO_EX_DATA` -- just two pointers.  We don't need to know
    /// the types of these; the API lets us treat them opaquely.
    ///
    /// This is _not_ owning.
    #[repr(C)]
    struct CRYPTO_EX_DATA {
        ctx: *mut c_void,
        sk: *mut c_void,
    }

    impl Default for CRYPTO_EX_DATA {
        fn default() -> Self {
            Self {
                ctx: ptr::null_mut(),
                sk: ptr::null_mut(),
            }
        }
    }

    // See `crypto.h`
    const CRYPTO_EX_INDEX_SSL: c_int = 0;
    const CRYPTO_EX_INDEX_SSL_CTX: c_int = 1;

    extern "C" {
        fn CRYPTO_new_ex_data(
            class_index: c_int,
            obj: *mut c_void,
            ed: *mut CRYPTO_EX_DATA,
        ) -> c_int;
        fn CRYPTO_set_ex_data(ed: *mut CRYPTO_EX_DATA, index: c_int, data: *mut c_void) -> c_int;
        fn CRYPTO_get_ex_data(ed: *const CRYPTO_EX_DATA, index: c_int) -> *mut c_void;
        fn CRYPTO_free_ex_data(class_index: c_int, obj: *mut c_void, ed: *mut CRYPTO_EX_DATA);
    }
}

/// In AWS-LC, ex_data classes for `SSL` and `SSL_CTX` belong to libssl, so
/// we implement them here: `SSL_get_ex_new_index`/`SSL_CTX_get_ex_new_index`
/// register indices (and free callbacks) in a per-class registry.
#[cfg(feature = "awslc")]
mod awslc_impl {
    use super::*;
    use std::sync::Mutex;

    pub type CryptoExFree = Option<
        unsafe extern "C" fn(
            parent: *mut c_void,
            ptr: *mut c_void,
            ad: *mut c_void,
            index: c_int,
            argl: core::ffi::c_long,
            argp: *mut c_void,
        ),
    >;

    #[derive(Clone)]
    struct Registered {
        argl: core::ffi::c_long,
        argp: usize,
        free: CryptoExFree,
    }

    struct Class {
        // index 0 is reserved for app data, as in AWS-LC
        items: Mutex<Vec<Registered>>,
    }

    impl Class {
        const fn new() -> Self {
            Self {
                items: Mutex::new(Vec::new()),
            }
        }

        fn register(
            &self,
            argl: core::ffi::c_long,
            argp: *mut c_void,
            free: CryptoExFree,
        ) -> c_int {
            let mut items = self.items.lock().unwrap();
            items.push(Registered {
                argl,
                argp: argp as usize,
                free,
            });
            items.len() as c_int
        }
    }

    static SSL_CLASS: Class = Class::new();
    static SSL_CTX_CLASS: Class = Class::new();

    pub fn new_ssl_index(argl: core::ffi::c_long, argp: *mut c_void, free: CryptoExFree) -> c_int {
        SSL_CLASS.register(argl, argp, free)
    }

    pub fn new_ssl_ctx_index(
        argl: core::ffi::c_long,
        argp: *mut c_void,
        free: CryptoExFree,
    ) -> c_int {
        SSL_CTX_CLASS.register(argl, argp, free)
    }

    pub struct ExData {
        slots: Vec<*mut c_void>,
        class: Option<&'static Class>,
        owner: *mut c_void,
    }

    impl ExData {
        pub fn new_ssl(ssl: *mut SSL) -> Option<Self> {
            Some(Self {
                slots: Vec::new(),
                class: Some(&SSL_CLASS),
                owner: ssl as *mut c_void,
            })
        }

        pub fn new_ssl_ctx(ctx: *mut SSL_CTX) -> Option<Self> {
            Some(Self {
                slots: Vec::new(),
                class: Some(&SSL_CTX_CLASS),
                owner: ctx as *mut c_void,
            })
        }

        pub fn set(&mut self, idx: c_int, data: *mut c_void) -> Result<(), Error> {
            let idx = usize::try_from(idx).map_err(|_| Error::bad_data("ex_data index"))?;
            if self.slots.len() <= idx {
                self.slots.resize(idx + 1, ptr::null_mut());
            }
            self.slots[idx] = data;
            Ok(())
        }

        pub fn get(&self, idx: c_int) -> *mut c_void {
            usize::try_from(idx)
                .ok()
                .and_then(|idx| self.slots.get(idx).copied())
                .unwrap_or_else(ptr::null_mut)
        }
    }

    impl Drop for ExData {
        fn drop(&mut self) {
            let Some(class) = self.class else {
                return;
            };
            // as in AWS-LC, every registered free callback is called, even for unset slots
            // snapshot, so a callback freeing another object of this class can't deadlock
            let items = class.items.lock().unwrap().clone();
            for (i, item) in items.iter().enumerate() {
                let idx = i + 1;
                if let Some(free) = item.free {
                    let value = self.slots.get(idx).copied().unwrap_or_else(ptr::null_mut);
                    unsafe {
                        free(
                            self.owner,
                            value,
                            ptr::null_mut(),
                            idx as c_int,
                            item.argl,
                            item.argp as *mut c_void,
                        )
                    };
                }
            }
        }
    }

    impl Default for ExData {
        fn default() -> Self {
            Self {
                slots: Vec::new(),
                class: None,
                owner: ptr::null_mut(),
            }
        }
    }
}
