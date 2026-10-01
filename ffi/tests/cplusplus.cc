// fips204.h must compile and link as C++. This calls the inline wrappers,
// which C++ compiles from the header itself.
#include <cstring>
#include <fips204.h>

int main() {
  ml_dsa_44_public_key pub;
  ml_dsa_44_private_key priv;
  ml_dsa_44_public_key pub_2;
  ml_dsa_44_signature sig;
  const uint8_t msg[] = { 'a', 's', 'd', 'f' };

  if (ml_dsa_44_keygen(&pub, &priv) != ML_DSA_OK)
    return 1;
  if (ml_dsa_44_get_public_key(&priv, &pub_2) != ML_DSA_OK)
    return 2;
  if (std::memcmp(&pub, &pub_2, sizeof(pub)) != 0)
    return 3;
  if (ml_dsa_44_sign_deterministic(&priv, msg, sizeof(msg), NULL, 0, &sig) != ML_DSA_OK)
    return 4;
  if (ml_dsa_44_verify(&pub, &sig, msg, sizeof(msg), NULL, 0) != ML_DSA_OK)
    return 5;
  return 0;
}
