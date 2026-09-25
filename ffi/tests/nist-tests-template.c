int
MLDSA_keygen_test(int tcId,
                  const ml_dsa_seed *seed,
                  const MLDSA_public_key *pub,
                  const MLDSA_private_key *priv) {
  ml_dsa_err err = 0;
  MLDSA_public_key pubout;
  MLDSA_private_key privout;
  ml_dsa_seed varseed;
  int errcount = 0;
  err = MLDSA_keygen_from_seed(seed, &pubout, &privout);
  if (err) {
    fprintf(stderr, "keyGen test %d failed with %d\n", tcId, err);
    return 1;
  }
  if (memcmp(&pubout, pub, sizeof(pubout))){
    fprintf(stderr, "public key in keyGen test %d did not match\n", tcId);
    errcount ++;
  }
  if (memcmp(&privout, priv, sizeof(privout))){
    fprintf(stderr, "private key in keyGen test %d did not match\n", tcId);
    errcount ++;
  }
  memcpy (&varseed, seed, sizeof(varseed));
  varseed.data[2]++;

  err = MLDSA_keygen_from_seed(&varseed, &pubout, &privout);
  if (err) {
    fprintf(stderr, "Variation of keyGen test %d failed with %d\n", tcId, err);
    return 1;
  }
  if (!memcmp(&pubout, pub, sizeof(pubout))){
    fprintf(stderr, "public key in varied keyGen test %d matched\n", tcId);
    errcount ++;
  }
  if (!memcmp(&privout, priv, sizeof(privout))){
    fprintf(stderr, "private key in varied keyGen test %d matched\n", tcId);
    errcount ++;
  }
  return errcount;
}
             

int
MLDSA_sigver_test(int tcId,
                  const MLDSA_public_key *pub,
                  const MLDSA_signature *sig,
                  const uint8_t *msg,
                  const size_t msglen,
                  const uint8_t *ctx,
                  const size_t ctxlen,
                  bool testpassed) {
  ml_dsa_err err = 0;
  err = MLDSA_verify(pub, sig, msg, msglen, ctx, ctxlen);
  if (err != ML_DSA_OK && err != ML_DSA_VERIFICATION_FAILURE) {
    fprintf(stderr, "sigVer test %d failed with surprising return code %d\n",
            tcId, err);
    return 1;
  }
  if ((bool)(!err) != testpassed) {
    fprintf(stderr, "sigVer test %d failed: return status %d, expected test to %s\n",
            tcId, err, (testpassed ? "pass" : "not pass"));
    return 1;
  }
  return 0;
}

int
MLDSA_siggen_test(int tcId,
                  const MLDSA_private_key *priv,
                  const MLDSA_signature *sig,
                  const uint8_t *msg,
                  const size_t msglen,
                  const uint8_t *ctx,
                  const size_t ctxlen) {
  ml_dsa_err err = 0;
  MLDSA_signature newsig;
  err = MLDSA_sign_deterministic(priv, msg, msglen, ctx, ctxlen, &newsig);
  if (err) {
    fprintf(stderr, "sigGen test %d failed with return code %d\n",
            tcId, err);
    return 1;
  }
  if (memcmp(&newsig, sig, sizeof(newsig))) {
    fprintf(stderr, "sigGen test %d failed: sigs didn't match\n", tcId);
    return 1;
  }
  return 0;
}
