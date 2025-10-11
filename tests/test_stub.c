#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

// Read the compiled stub and execute it
int main() {
    FILE *f = fopen("organull/complete_unpacking_stub_compiled.bin", "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    
    // Get file size
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    // Allocate memory with execute permissions
    void *code = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, 
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED) {
        perror("mmap");
        fclose(f);
        return 1;
    }
    
    // Read the stub into memory
    if (fread(code, 1, size, f) != size) {
        perror("fread");
        munmap(code, size);
        fclose(f);
        return 1;
    }
    
    fclose(f);
    
    printf("Stub loaded at %p, size %ld\n", code, size);
    printf("First 16 bytes: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", ((unsigned char*)code)[i]);
    }
    printf("\n");
    
    // Try to execute the stub
    // This will likely fail because the parameters are not set up correctly
    // But we can at least see if it starts executing
    void (*stub)() = (void(*)())code;
    
    printf("Calling stub...\n");
    fflush(stdout);
    
    // This is dangerous but we're just trying to see what happens
    stub();
    
    printf("Stub returned\n");
    
    munmap(code, size);
    return 0;
}