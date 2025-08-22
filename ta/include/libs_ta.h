// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#ifndef TA_LIBS_EXAMPLE_H
#define TA_LIBS_EXAMPLE_H

#define TA_LIBS_EXAMPLE_UUID \
	{ 0x19038f64, 0x871d, 0x4773, \
		{ 0xb1, 0xf5, 0x87, 0x86, 0x97, 0x74, 0x5e, 0xee} }
#define TA_SM2_TEST_R  0
#define TA_SM3_TEST_R  1
#define TA_IDENTIFY_DEPKEY_R 3
#define TA_IDENTIFY_ENKID 2
#define TA_IDENTIFY_GENSK_S 4
#define TA_IDENTIFY_DEPKEY 5
#define TA_IDENTIFY_EXCHANGER 6
#define TA_IDENTIFY_CONFIRM_S 7


#define TA_SIG_KEYPAIR 11
#define TA_KEM_KEYPAIR 12
#define TA_AUTHEN_ENCAPE 13
#define TA_AUTHEN_DECAPE 14
#define TA_SAVE_OPPOSIGPK 15

#endif /*TA_LIBS_EXAMPLE_H*/
