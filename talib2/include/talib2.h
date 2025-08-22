// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */
#ifndef TALIB2_H
#define TALIB2_H

#include "aes256ctr.h"
#include "cbd.h"
#include "kex.h"
#include "fips202.h"
#include "indcpa.h"
#include "ntt.h"
#include "symmetric.h"
#include "sha2.h"
#include "kex.h"
#include "kem.h"


void talib2_func(void);
void talib2_panic(void);

#endif /*TALIB2_H*/
