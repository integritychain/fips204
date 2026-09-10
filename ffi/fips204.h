#ifndef __FIPS204_H__
#define __FIPS204_H__
/*
  Minimalist ML-DSA C interface
  Author: Daniel Kahn Gillmor <dkg@fifthhorseman.net>

  Memory allocation and tracking are entirely the job of the caller.

  The shared object backing this interface has no internal state
  between calls, and should be completely reentrant.

  These functions return 0 (ML_DSA_OK) on success, or a more specific
  non-zero octet on error.
*/
#include <stdint.h>

typedef uint8_t ml_dsa_err;

const ml_dsa_err ML_DSA_OK = 0;
const ml_dsa_err ML_DSA_NULL_PTR_ERROR = 1;
const ml_dsa_err ML_DSA_SERIALIZATION_ERROR = 2;
const ml_dsa_err ML_DSA_DESERIALIZATION_ERROR = 3;
const ml_dsa_err ML_DSA_KEYGEN_ERROR = 4;
const ml_dsa_err ML_DSA_SIGN_ERROR = 5;
const ml_dsa_err ML_DSA_VERIFICATION_ERROR = 6;
const ml_dsa_err ML_DSA_VERIFICATION_FAILURE = 7;


typedef struct ml_dsa_seed {
  uint8_t data[32];
} ml_dsa_seed;


typedef struct ml_dsa_44_private_key {
  uint8_t data[2560];
} ml_dsa_44_private_key;
typedef struct ml_dsa_44_public_key {
  uint8_t data[1312];
} ml_dsa_44_public_key;
typedef struct ml_dsa_44_signature {
  uint8_t data[2420];
} ml_dsa_44_signature;

typedef struct ml_dsa_65_private_key {
  uint8_t data[4032];
} ml_dsa_65_private_key;
typedef struct ml_dsa_65_public_key {
  uint8_t data[1952];
} ml_dsa_65_public_key;
typedef struct ml_dsa_65_signature {
  uint8_t data[3309];
} ml_dsa_65_signature;

typedef struct ml_dsa_87_private_key {
  uint8_t data[4896];
} ml_dsa_87_private_key;
typedef struct ml_dsa_87_public_key {
  uint8_t data[2592];
} ml_dsa_87_public_key;
typedef struct ml_dsa_87_signature {
  uint8_t data[4627];
} ml_dsa_87_signature;

#ifdef  __cplusplus
extern "C" {
#endif


ml_dsa_err ml_dsa_populate_seed(ml_dsa_seed *seed_out);

/* ML-DSA-44 */
ml_dsa_err ml_dsa_44_keygen(ml_dsa_44_public_key *public_out,
                            ml_dsa_44_private_key *private_out);

ml_dsa_err ml_dsa_44_keygen_from_seed(const ml_dsa_seed *d_z,
                                      ml_dsa_44_public_key *public_out,
                                      ml_dsa_44_private_key *private_out);

ml_dsa_err ml_dsa_44_sign(const ml_dsa_44_private_key *private,
                          const uint8_t *message,
                          size_t message_size,
                          const uint8_t *context,
                          size_t context_size,
                          ml_dsa_44_signature *signature_out);

ml_dsa_err ml_dsa_44_sign_deterministic(const ml_dsa_44_private_key *private,
                                        const uint8_t *message,
                                        size_t message_size,
                                        const uint8_t *context,
                                        size_t context_size,
                                        ml_dsa_44_signature *signature_out);

ml_dsa_err ml_dsa_44_verify(const ml_dsa_44_public_key *public,
                            const ml_dsa_44_signature *signature,
                            const uint8_t *message,
                            size_t message_size,
                            const uint8_t *context,
                            size_t context_size);

/* ML-DSA-65 */
ml_dsa_err ml_dsa_65_keygen(ml_dsa_65_public_key *public_out,
                            ml_dsa_65_private_key *private_out);

ml_dsa_err ml_dsa_65_keygen_from_seed(const ml_dsa_seed *d_z,
                                      ml_dsa_65_public_key *public_out,
                                      ml_dsa_65_private_key *private_out);

ml_dsa_err ml_dsa_65_sign(const ml_dsa_65_private_key *private,
                          const uint8_t *message,
                          size_t message_size,
                          const uint8_t *context,
                          size_t context_size,
                          ml_dsa_65_signature *signature_out);

ml_dsa_err ml_dsa_65_sign_deterministic(const ml_dsa_65_private_key *private,
                                        const uint8_t *message,
                                        size_t message_size,
                                        const uint8_t *context,
                                        size_t context_size,
                                        ml_dsa_65_signature *signature_out);

ml_dsa_err ml_dsa_65_verify(const ml_dsa_65_public_key *public,
                            const ml_dsa_65_signature *signature,
                            const uint8_t *message,
                            size_t message_size,
                            const uint8_t *context,
                            size_t context_size);

/* ML-DSA-87 */
ml_dsa_err ml_dsa_87_keygen(ml_dsa_87_public_key *public_out,
                            ml_dsa_87_private_key *private_out);

ml_dsa_err ml_dsa_87_keygen_from_seed(const ml_dsa_seed *d_z,
                                      ml_dsa_87_public_key *public_out,
                                      ml_dsa_87_private_key *private_out);

ml_dsa_err ml_dsa_87_sign(const ml_dsa_87_private_key *private,
                          const uint8_t *message,
                          size_t message_size,
                          const uint8_t *context,
                          size_t context_size,
                          ml_dsa_87_signature *signature_out);

ml_dsa_err ml_dsa_87_sign_deterministic(const ml_dsa_87_private_key *private,
                                        const uint8_t *message,
                                        size_t message_size,
                                        const uint8_t *context,
                                        size_t context_size,
                                        ml_dsa_87_signature *signature_out);

ml_dsa_err ml_dsa_87_verify(const ml_dsa_87_public_key *public,
                            const ml_dsa_87_signature *signature,
                            const uint8_t *message,
                            size_t message_size,
                            const uint8_t *context,
                            size_t context_size);


#ifdef  __cplusplus
} /* extern "C" */
#endif
#endif /* __FIPS204_H__ */
