#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

int main() {
    // Open the compiled stub binary
    int fd = open("organull/test_text.bin", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return 1;
    }
    
    // Get the file size
    struct stat sb;
    if (fstat(fd, &sb) == -1) {
        perror("fstat");
        close(fd);
        return 1;
    }
    
    // Map the file into memory
    void *mapped = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapped == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }
    
    // Allocate executable memory
    void *mem = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        munmap(mapped, sb.st_size);
        close(fd);
        return 1;
    }
    
    // Copy the stub to the executable memory
    memcpy(mem, mapped, sb.st_size);
    
    // Close the file and unmap the file mapping
    munmap(mapped, sb.st_size);
    close(fd);
    
    // Fork a child process to execute the stub
    pid_t pid = fork();
    if (pid == 0) {
        // Child process - execute the stub
        printf("Executing stub in child process...\n");
        ((void(*)())mem)();
        // If we reach here, the stub didn't exit
        printf("Stub returned normally\n");
        exit(0);
    } else if (pid > 0) {
        // Parent process - wait for child to finish
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            printf("Stub exited with code %d\n", exit_code);
        } else if (WIFSIGNALED(status)) {
            int signal = WTERMSIG(status);
            printf("Stub terminated by signal %d\n", signal);
        } else {
            printf("Stub terminated for unknown reason\n");
        }
    } else {
        perror("fork");
        return 1;
    }
    
    // Cleanup
    munmap(mem, sb.st_size);
    
    return 0;
}