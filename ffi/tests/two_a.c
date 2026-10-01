#include <fips204.h>

int from_b(void);

int main(void) {
  if (ml_dsa_44_keygen(NULL, NULL) == ML_DSA_OK)
    return 1;
  if (from_b() != ML_DSA_SHA2_256[0])
    return 2;
  return 0;
}
