#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

int main() {
    // Print the page size
    printf("Page size: %ld\n", sysconf(_SC_PAGESIZE));
    
    // Allocate some memory
    void *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    
    printf("Allocated memory at: %p\n", ptr);
    
    // Write some data to the memory
    *(volatile char*)ptr = 0x42;
    printf("Wrote data to memory\n");
    
    // Unmap the memory
    if (munmap(ptr, 4096) == -1) {
        perror("munmap");
        return 1;
    }
    
    printf("Unmapped memory\n");
    return 0;
}