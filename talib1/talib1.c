//
// Created by xy on 10/29/2021
//

#include "talib1.h"

void test_strlen(void)
{
	char c[1000] = "dasfdasfasfgasgfsijfghduiasfbhuilas";
	printf("%d", strlen(c));
}

void test_strcpy(void)
{
	char c[1000] = "dasfdasfasfgasgfsijfghduiasfbhuilas";
	char b[1000];
	strcpy(b, c);
}

uint32_t test_unsignedInt(void)
{
	static unsigned int i = 0xFF;
	return i;
}


void talib1_func(void)
{
	printf("talib1_func()\n");
}


void test_sm3hash(void)
{
	const uint8_t* str = (uint8_t *)"abc";
	uint8_t output[32] = { 0 };
	sm3(str, sizeof(str), output);
}
