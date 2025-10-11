#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    int fd = open("/home/mrnob0dy666/greenbay/packed_ls_test_fixed5", O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    // Get file size
    off_t size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    // Map the file into memory
    void *mapped = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapped == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }

    // Find the entry point
    // For now, we'll just try to execute at offset 0x64000 from the start of the file
    // This is a simplification and may not work correctly
    void *entry_point = (char *)mapped + 0x24000; // Offset of .stub section in file
    
    printf("Mapped at %p, entry point at %p\n", mapped, entry_point);
    
    // Try to execute
    // This is very simplified and will likely fail
    // We're just trying to see if we can get more information about the segfault
    ((void(*)())entry_point)();
    
    // Cleanup
    munmap(mapped, size);
    close(fd);
    return 0;
}