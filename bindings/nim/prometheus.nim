# Prometheus FFI.
# This work is dedicated to the public domain under CC0 1.0 Universal.

type
  PromArchitecture* {.size: sizeof(cint).} = enum
    promArchX86 = 0
    promArchX64 = 1

  PromSyntax* {.size: sizeof(cint).} = enum
    promSyntaxIntel = 0
    promSyntaxATT = 1

  PromInstruction* {.bycopy.} = object
    address*: uint64
    length*: uint8
    is_branch*: bool
    is_call*: bool
    is_vector*: bool
    branch_target*: uint64

  PromDecoder* = object # Opaque

  PromSymbolResolverCallback* = proc(context: pointer, address: uint64, out_buffer: cstring, max_len: csize_t): bool {.cdecl.}

  PromSymbolResolver* {.bycopy.} = object
    context*: pointer
    resolve*: PromSymbolResolverCallback

# Library resolution.
const libName = 
  when defined(windows): "prometheus.dll"
  elif defined(macosx): "libprometheus.dylib"
  else: "libprometheus.so"

proc prom_decoder_create*(arch: PromArchitecture): ptr PromDecoder {.cdecl, dynlib: libName, importc: "prom_decoder_create".}
proc prom_decoder_destroy*(decoder: ptr PromDecoder) {.cdecl, dynlib: libName, importc: "prom_decoder_destroy".}
proc prom_decode_and_format*(decoder: ptr PromDecoder, buffer: ptr uint8, buffer_len: csize_t, address: uint64, syntax: PromSyntax, resolver: ptr PromSymbolResolver, out_string: cstring, out_string_max_len: csize_t, out_instruction: ptr PromInstruction): bool {.cdecl, dynlib: libName, importc: "prom_decode_and_format".}

when isMainModule:
  import strformat

  echo "init: prom_nim"
  let decoder = prom_decoder_create(promArchX64)
  
  # [B8 01 00 00 00]
  var code: array[5, uint8] = [0xB8'u8, 0x01, 0x00, 0x00, 0x00]
  var outStr = newString(256)
  var inst: PromInstruction

  let success = prom_decode_and_format(
    decoder,
    addr code[0],
    cast[csize_t](code.len),
    0x1000'u64,
    promSyntaxIntel,
    nil,
    outStr.cstring,
    cast[csize_t](outStr.len),
    addr inst
  )

  if success:
    echo fmt"[{inst.address:#x}] {outStr.cstring}"
  else:
    echo "Decode failed"
    
  prom_decoder_destroy(decoder)
