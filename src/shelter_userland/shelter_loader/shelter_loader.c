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

#define SHELTER_DEBUG 0
#define ENC_MEM_ALLOCATE	_IOW('m', 1, unsigned int)
#define ENC_MEM_RELEASE		_IOW('m', 2, unsigned int)
#define ENC_PATH		"/dev/SHELTER"

#define __NR_shelter_exec 436

struct ENC_demo_info {
	unsigned long enc_id;
	unsigned long virt;
	unsigned long phys;
	unsigned long offset;
	unsigned long length;
    unsigned long entry;
    unsigned long stack_top;
};

int main(int argc, char *argv[], char *envp[])
{
	if (argc < 2) {
        printf("usage: shelter_loader /path-to/SApp\n");
        return 1;
    }
	printf("[DEBUG]PID=%d\n", getpid());
	/*test app*/
	char* elf_path= argv[1];
    char *cmd[] = {elf_path,NULL};

    struct ENC_demo_info region;
	int fd_cma;

	fd_cma = open(ENC_PATH, O_RDWR, 0);
	printf("fd_cmd:%d\n", fd_cma);
	if (fd_cma < 0) {
		printf("Can't open %s\n", ENC_PATH);
		return -1;
	}

	if (ioctl(fd_cma, ENC_MEM_RELEASE, 0) < 0) {
		printf("SHELTER_MEM_RELEASE: ioctl failed\n");
		return -1;
	}

    /*disable close_on_exec*/
    int flags = fcntl(fd_cma, F_GETFD);
    flags &= ~FD_CLOEXEC;
    fcntl(fd_cma, F_SETFD, flags);

    memset(&region, 0, sizeof(region));
	region.length = 0x400000;

	/* Allocate CMA memory for shelter */
	if (ioctl(fd_cma, ENC_MEM_ALLOCATE, &region) < 0) {
		printf("SHELTER_MEM_ALLOCATE: ioctl failed\n");
		return -1;
	}

	//load the SApp to run
    syscall(__NR_shelter_exec, fd_cma, elf_path, cmd, NULL);    
	close(fd_cma);
	return 0;
}