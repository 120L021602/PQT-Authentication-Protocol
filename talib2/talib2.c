// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include <stdio.h>
#include <tee_internal_api.h>
#include "talib2.h"

void talib2_func(void)
{
	for(int i=1;i<50;i++){
		printf("talib2_func()\n");
		TEE_Wait(1500);
	}
}

void talib2_panic(void)
{
	printf("Calling TEE_Panic(0)\n");
	TEE_Panic(0);
}
