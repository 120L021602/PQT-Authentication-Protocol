//
// Created by xy on 10/29/2021
//

#include "libmath.h"
#include <assert.h>

int Ceil(double num)
{
    assert(num > 0);
    int n = (int)num;
    if(num - n > 0)
    	return n+1;
    else
    	return n;
}

int Floor(double num)
{
    assert(num > 0);
    int n = (int)num;
    return n;
}

