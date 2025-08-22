#ifndef MTWISTER_H_KEM
#define MTWISTER_H_KEM

#include "stdint.h"
#include "string.h"

#define STATE_VECTOR_LENGTH 624
#define STATE_VECTOR_M      397 /* changes to STATE_VECTOR_LENGTH also require changes to this */

typedef struct tagMTRand {
  uint32_t mt[STATE_VECTOR_LENGTH];
  int index;
} MTRand;

MTRand seedRand(uint32_t seed);
uint32_t genRandLong(MTRand* rand);
double genRand(MTRand* rand);

void RandomGen(uint32_t seed, size_t len, uint8_t *output);

#endif
