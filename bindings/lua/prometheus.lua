-- Prometheus FFI.
-- This work is dedicated to the public domain under CC0 1.0 Universal.
-- Requires LuaJIT

local ffi = require("ffi")

ffi.cdef[[
    typedef enum {
        PROM_ARCH_X86 = 0,
        PROM_ARCH_X64 = 1,
    } PromArchitecture;

    typedef enum {
        PROM_SYNTAX_INTEL = 0,
        PROM_SYNTAX_ATT = 1,
    } PromSyntax;

    typedef struct {
        uint64_t address;
        uint8_t length;
        bool is_branch;
        bool is_call;
        bool is_vector;
        uint64_t branch_target;
    } PromInstruction;

    typedef void PromDecoder;

    typedef struct {
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
]]

local lib_path
if ffi.os == "Windows" then
    lib_path = "../../target/release/prometheus.dll"
elseif ffi.os == "OSX" then
    lib_path = "../../target/release/libprometheus.dylib"
else
    lib_path = "../../target/release/libprometheus.so"
end

local prom = ffi.load(lib_path)

local decoder = prom.prom_decoder_create(prom.PROM_ARCH_X64)

local code = ffi.new("uint8_t[5]", {0xB8, 0x01, 0x00, 0x00, 0x00})
local out_str = ffi.new("char[256]")
local inst = ffi.new("PromInstruction")

print("init: prom_lua")

local success = prom.prom_decode_and_format(
    decoder,
    code,
    5,
    0x1000,
    prom.PROM_SYNTAX_INTEL,
    nil,
    out_str,
    256,
    inst
)

if success then
    print(string.format("[0x%x] %s", tonumber(inst.address), ffi.string(out_str)))
else
    print("Decode failed")
end

prom.prom_decoder_destroy(decoder)
