#ifndef NTT_H_SIG
#define NTT_H_SIG

#include <stdint.h>
#include "params.h"

#define ntt DILITHIUM_NAMESPACE(ntt)
void ntt(int32_t a[N]);

#define invntt_tomont DILITHIUM_NAMESPACE(invntt_tomont)
void invntt_tomont(int32_t a[N]);

#endif
