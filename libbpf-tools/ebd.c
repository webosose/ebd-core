#include <argp.h>
#include <stdio.h>
#include <string.h>
#include "ebd.h"

static struct env {
	int verbose;
} env = {
	.verbose = 0,
};

const char argp_program_doc[] =
"Under Construction";

int main(int argc, char *argv[])
{
	if (!strcmp(argv[1], "memleak"))
		memleak_main(argc - 1, argv + 1);

	if (!strcmp(argv[1], "lsan"))
		lsan_main(argc - 1, argv + 1);

	return 0;
}