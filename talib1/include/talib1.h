// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */
#ifndef TALIB1_H
#define TALIB1_H

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include "sm2.h"
#include "sm3.h"
#include "sm4.h"
#include "pkey.h"
#include "otp.h"

void talib1_func(void);

void test_strlen(void);

void test_strcpy(void);

void test_sm3hash(void);

uint32_t test_unsignedInt(void);

#endif /*TALIB1_H*/