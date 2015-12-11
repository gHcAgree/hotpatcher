#include <stdio.h>
#include "utils.h"

int hello(int user)
{
    char buf[64];

    sprintf(buf, "%s%d", "goodbye ", user);
	hdebug(buf);

    printf("CHANGED\n");

	return 111;
}
