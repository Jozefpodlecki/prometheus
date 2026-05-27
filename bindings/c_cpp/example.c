/* Prometheus FFI. */
/* This work is dedicated to the public domain under CC0 1.0 Universal. */

#include <stdio.h>
#include <string.h>
#include "../../include/prometheus.h"

bool resolve_symbol(void* context, uint64_t address, char* out_buffer, size_t max_len) {
    if (address == 0x140001000) {
        const char* sym = "kernel32!VirtualAlloc";
        if (strlen(sym) < max_len) {
            strcpy(out_buffer, sym);
            return true;
        }
    }
    return false;
}

int main() {
    printf("init: prom_c\n");

    PromDecoder* decoder = prom_decoder_create(PROM_ARCH_X64);
    if (!decoder) {
        printf("Failed to create decoder.\n");
        return 1;
    }

    uint8_t code[] = { 0xE8, 0xFB, 0x0F, 0x00, 0x40 }; // CALL rel32
    char out_str[256];
    PromInstruction inst;
    
    PromSymbolResolver resolver;
    resolver.context = NULL;
    resolver.resolve = resolve_symbol;

    bool success = prom_decode_and_format(
        decoder,
        code,
        sizeof(code),
        0x100000000ULL,
        PROM_SYNTAX_INTEL,
        &resolver,
        out_str,
        sizeof(out_str),
        &inst
    );

    if (success) {
        printf("[0x%llx] %s\n", inst.address, out_str);
    } else {
        printf("Decode failed.\n");
    }

    prom_decoder_destroy(decoder);
    return 0;
}
