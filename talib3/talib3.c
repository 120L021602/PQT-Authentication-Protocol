// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include "talib3.h"
#include <stdio.h>
#include <unistd.h>
#include <tee_internal_api.h>

void talib3_func(void)
{
	for(int i=1;i<15;i++){
		printf("This is talib3_func()\n");
		TEE_Wait(1000);
	}
}
