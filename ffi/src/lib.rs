use paste::paste;
use rand_core::{OsRng, RngCore};

mod ret {
    pub const OK: u8 = 0;
    pub const NULL_PTR_ERROR: u8 = 1;
    // pub const SERIALIZATION_ERROR: u8 = 2; // can't be reached
    pub const DESERIALIZATION_ERROR: u8 = 3;
    pub const KEYGEN_ERROR: u8 = 4;
    pub const SIGN_ERROR: u8 = 5;
    // pub const VERIFICATION_ERROR: u8 = 6; // can't be reached
    pub const VERIFICATION_FAILURE: u8 = 7;
}

#[repr(C)]
pub struct ml_dsa_seed {
    data: [u8; 32],
}

#[no_mangle]
pub extern "C" fn ml_dsa_populate_seed(seed_out: Option<&mut ml_dsa_seed>) -> u8 {
    use ret;
    let Some(seed_out) = seed_out else {
        return ret::NULL_PTR_ERROR;
    };
    OsRng.fill_bytes(&mut seed_out.data);
    ret::OK
}

macro_rules! slice_from_c_buf {
    ($ptr:ident, $len:ident) => {
        if $len == 0 {
            &[]
        } else {
            if $ptr.is_null() {
                return ret::NULL_PTR_ERROR;
            } else {
                unsafe { std::slice::from_raw_parts($ptr, $len) }
            }
        }
    };
}

macro_rules! parameter_set {
    ($pc:ident) => {
        mod $pc {
            use crate::ret;
            use crate::ml_dsa_seed;

            #[repr(C)]
            pub struct c_private_key {
                data: [u8; fips204::$pc::SK_LEN],
            }
            #[repr(C)]
            pub struct c_public_key {
                data: [u8; fips204::$pc::PK_LEN],
            }
            #[repr(C)]
            pub struct c_signature {
                data: [u8; fips204::$pc::SIG_LEN],
            }

            pub fn keygen(
                seed: Option<&ml_dsa_seed>,
                public_out: Option<&mut c_public_key>,
                private_out: Option<&mut c_private_key>,
            ) -> u8 {
                use fips204::traits::{KeyGen, SerDes};

                let (Some(public_out), Some(private_out)) = (public_out, private_out) else {
                    return ret::NULL_PTR_ERROR;
                };

                let (pubkey, privkey) = match seed {
                    None => { let Ok((pubkey, privkey)) =
                              fips204::$pc::KG::try_keygen() else {
                                  return ret::KEYGEN_ERROR;
                              };
                              (pubkey, privkey)
                    },
                    Some(seed) => fips204::$pc::KG::keygen_from_seed(&seed.data),
                };

                public_out.data = pubkey.into_bytes();
                private_out.data = privkey.into_bytes();
                ret::OK
            }


            pub fn sign(
                private: Option<&c_private_key>,
                message: *const u8,
                message_size: usize,
                context: *const u8,
                context_size: usize,
                signature_out: Option<&mut c_signature>,
                deterministic: bool,
            ) -> u8 {
                use fips204::traits::{Signer, SerDes};

                let (Some(private), Some(signature_out)) =
                    (private, signature_out)
                else {
                    return ret::NULL_PTR_ERROR;
                };

                let msg = slice_from_c_buf!(message, message_size);
                let ctx = slice_from_c_buf!(context, context_size);

                let Ok(privkey) = fips204::$pc::PrivateKey::try_from_bytes(private.data) else {
                    return ret::DESERIALIZATION_ERROR;
                };
                let ans = if deterministic {
                    let s: [u8; 32] = [ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 ];
                    privkey.try_sign_with_seed(&s, msg, ctx)
                } else {
                    privkey.try_sign(msg, ctx)
                };
                let Ok(sig) = ans else {
                    return ret::SIGN_ERROR;
                };

                signature_out.data = sig;
                ret::OK
            }

            pub fn verify(
                public: Option<&c_public_key>,
                signature: Option<&c_signature>,
                message: *const u8,
                message_size: usize,
                context: *const u8,
                context_size: usize,
            ) -> u8 {
                use fips204::traits::{Verifier, SerDes};

                let (Some(public), Some(signature)) =
                    (public, signature)
                else {
                    return ret::NULL_PTR_ERROR;
                };

                let msg = slice_from_c_buf!(message, message_size);
                let ctx = slice_from_c_buf!(context, context_size);

                let Ok(pubkey) = fips204::$pc::PublicKey::try_from_bytes(public.data) else {
                    return ret::DESERIALIZATION_ERROR;
                };

                if pubkey.verify(msg, &signature.data, ctx) {
                    ret::OK
                } else {
                    ret::VERIFICATION_FAILURE
                }
            }
        }

        paste! {
        #[no_mangle]
        pub extern "C" fn [<$pc _keygen>] (
            public_out: Option<&mut $pc::c_public_key>,
            private_out: Option<&mut $pc::c_private_key>,
        ) -> u8 {
            $pc::keygen(None, public_out, private_out)
        }

        #[no_mangle]
        pub extern "C" fn [<$pc _keygen_from_seed>] (
            seed: Option<&ml_dsa_seed>,
            public_out: Option<&mut $pc::c_public_key>,
            private_out: Option<&mut $pc::c_private_key>,
        ) -> u8 {
            let Some(seed) = seed else {
                return ret::NULL_PTR_ERROR;
            };
            $pc::keygen(Some(seed), public_out, private_out)
        }

        #[no_mangle]
        pub extern "C" fn [<$pc _sign>] (
            private: Option<&$pc::c_private_key>,
            message: *const u8,
            message_size: usize,
            context: *const u8,
            context_size: usize,
            signature_out: Option<&mut $pc::c_signature>,
        ) -> u8 {
            $pc::sign(private, message, message_size, context, context_size, signature_out, false)
        }

        #[no_mangle]
        pub extern "C" fn [<$pc _sign_deterministic>] (
            private: Option<&$pc::c_private_key>,
            message: *const u8,
            message_size: usize,
            context: *const u8,
            context_size: usize,
            signature_out: Option<&mut $pc::c_signature>,
        ) -> u8 {
            $pc::sign(private, message, message_size, context, context_size, signature_out, true)
        }

        #[no_mangle]
        pub extern "C" fn [<$pc _verify>] (
            public: Option<&$pc::c_public_key>,
            signature: Option<&$pc::c_signature>,
            message: *const u8,
            message_size: usize,
            context: *const u8,
            context_size: usize,
        ) -> u8 {
            $pc::verify(public, signature, message, message_size, context, context_size)
        }
    }
    };
}

parameter_set!(ml_dsa_44);
parameter_set!(ml_dsa_65);
parameter_set!(ml_dsa_87);
