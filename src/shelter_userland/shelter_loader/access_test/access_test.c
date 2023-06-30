#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <elf.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#define ENC_PATH		"/dev/SHELTER"
#define ENC_ISOLATION_TEST   0x80001001

int main()
{
    int fd_cma = open(ENC_PATH, O_RDWR, 0);
	printf("fd_cmd:%d\n", fd_cma);
	if (fd_cma < 0) {
		printf("Can't open %s\n", ENC_PATH);
		return -1;
	}

	if (ioctl(fd_cma, ENC_ISOLATION_TEST, 0) < 0) {
		return -1;
	}

    close(fd_cma);
    printf("finish test\n");
	return 0;
}

