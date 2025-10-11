#include <stdio.h>
#include <stdint.h>

// Mock the parameter area structure
struct parameter_area {
    uint64_t key_part1;
    uint64_t key_part2;
    uint64_t key_part3;
    uint64_t key_part4;
    uint8_t nonce[12];
    uint32_t ca_steps;
    uint64_t payload_rva;
    uint64_t payload_size;
    uint64_t stub_rva;
};

int main() {
    // Create a mock parameter area
    struct parameter_area params = {
        .key_part1 = 0x1111111111111111,
        .key_part2 = 0x2222222222222222,
        .key_part3 = 0x3333333333333333,
        .key_part4 = 0x4444444444444444,
        .nonce = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C},
        .ca_steps = 100,
        .payload_rva = 0x00000000000a5000,
        .payload_size = 0x0000000000021be8,
        .stub_rva = 0x0000000000064000
    };
    
    // Print the offsets
    printf("Parameter area offsets:\n");
    printf("key_part1 offset: %ld\n", (char*)&params.key_part1 - (char*)&params);
    printf("key_part2 offset: %ld\n", (char*)&params.key_part2 - (char*)&params);
    printf("key_part3 offset: %ld\n", (char*)&params.key_part3 - (char*)&params);
    printf("key_part4 offset: %ld\n", (char*)&params.key_part4 - (char*)&params);
    printf("nonce offset: %ld\n", (char*)&params.nonce - (char*)&params);
    printf("ca_steps offset: %ld\n", (char*)&params.ca_steps - (char*)&params);
    printf("payload_rva offset: %ld\n", (char*)&params.payload_rva - (char*)&params);
    printf("payload_size offset: %ld\n", (char*)&params.payload_size - (char*)&params);
    printf("stub_rva offset: %ld\n", (char*)&params.stub_rva - (char*)&params);
    
    // Print the values
    printf("\nParameter values:\n");
    printf("key_part1: 0x%016lx\n", params.key_part1);
    printf("key_part2: 0x%016lx\n", params.key_part2);
    printf("key_part3: 0x%016lx\n", params.key_part3);
    printf("key_part4: 0x%016lx\n", params.key_part4);
    printf("ca_steps: %u\n", params.ca_steps);
    printf("payload_rva: 0x%016lx\n", params.payload_rva);
    printf("payload_size: 0x%016lx\n", params.payload_size);
    printf("stub_rva: 0x%016lx\n", params.stub_rva);
    
    return 0;
}