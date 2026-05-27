/*
** Prometheus FFI.
** This work is dedicated to the public domain under CC0 1.0 Universal.
*/

#ifndef PROMETHEUS_H
#define PROMETHEUS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum PromArchitecture {
    PROM_ARCH_X86 = 0,
    PROM_ARCH_X64 = 1,
} PromArchitecture;

typedef enum PromSyntax {
    PROM_SYNTAX_INTEL = 0,
    PROM_SYNTAX_ATT = 1,
} PromSyntax;

typedef struct PromInstruction {
    uint64_t address;
    uint8_t length;
    bool is_branch;
    bool is_call;
    bool is_vector;
    uint64_t branch_target;
} PromInstruction;

typedef struct PromDecoder PromDecoder;

typedef struct PromSymbolResolver {
    void* context;
    bool (*resolve)(void* context, uint64_t address, char* out_buffer, size_t max_len);
} PromSymbolResolver;

PromDecoder* prom_decoder_create(PromArchitecture arch);

void prom_decoder_destroy(PromDecoder* decoder);

bool prom_decode_and_format(
    PromDecoder* decoder,
    const uint8_t* buffer,
    size_t buffer_len,
    uint64_t address,
    PromSyntax syntax,
    const PromSymbolResolver* resolver,
    char* out_string,
    size_t out_string_max_len,
    PromInstruction* out_instruction
);

#ifdef __cplusplus
}
#endif

#endif // PROMETHEUS_H
