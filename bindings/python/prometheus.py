# Prometheus FFI.
# This work is dedicated to the public domain under CC0 1.0 Universal.

import ctypes
import os
import sys

# Arch constants.
PROM_ARCH_X86 = 0
PROM_ARCH_X64 = 1

PROM_SYNTAX_INTEL = 0
PROM_SYNTAX_ATT = 1

class PromInstruction(ctypes.Structure):
    _fields_ = [
        ("address", ctypes.c_uint64),
        ("length", ctypes.c_uint8),
        ("is_branch", ctypes.c_bool),
        ("is_call", ctypes.c_bool),
        ("is_vector", ctypes.c_bool),
        ("branch_target", ctypes.c_uint64),
    ]

# FFI callback signature.
RESOLVE_CALLBACK = ctypes.CFUNCTYPE(
    ctypes.c_bool,
    ctypes.c_void_p,
    ctypes.c_uint64,
    ctypes.c_void_p,
    ctypes.c_size_t
)

class PromSymbolResolver(ctypes.Structure):
    _fields_ = [
        ("context", ctypes.c_void_p),
        ("resolve", RESOLVE_CALLBACK)
    ]

class PrometheusDecoder:
    def __init__(self, dll_path=None, arch=PROM_ARCH_X64):
        if dll_path is None:
            # Resolve dynamic library.
            base_path = os.path.join(os.path.dirname(__file__), "..", "..", "target", "release")
            if sys.platform == "win32":
                dll_path = os.path.join(base_path, "prometheus.dll")
            elif sys.platform == "darwin":
                dll_path = os.path.join(base_path, "libprometheus.dylib")
            else:
                dll_path = os.path.join(base_path, "libprometheus.so")
                
        self.lib = ctypes.CDLL(dll_path)
        
        # Ctypes mapping.
        self.lib.prom_decoder_create.argtypes = [ctypes.c_int]
        self.lib.prom_decoder_create.restype = ctypes.c_void_p
        
        self.lib.prom_decoder_destroy.argtypes = [ctypes.c_void_p]
        self.lib.prom_decoder_destroy.restype = None
        
        self.lib.prom_decode_and_format.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.c_uint64,
            ctypes.c_int,
            ctypes.POINTER(PromSymbolResolver),
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.POINTER(PromInstruction)
        ]
        self.lib.prom_decode_and_format.restype = ctypes.c_bool
        
        self.decoder_ptr = self.lib.prom_decoder_create(arch)
        
    def __del__(self):
        if hasattr(self, 'decoder_ptr') and self.decoder_ptr:
            self.lib.prom_decoder_destroy(self.decoder_ptr)
            
    def decode(self, code_bytes, address=0x1000, syntax=PROM_SYNTAX_INTEL, symbol_resolver=None):
        buffer = (ctypes.c_uint8 * len(code_bytes)).from_buffer_copy(code_bytes)
        
        out_str = ctypes.create_string_buffer(256)
        out_inst = PromInstruction()
        
        resolver_ptr = None
        
        # Pin callback reference to prevent GC
        self._last_callback = None
        
        if symbol_resolver:
            def py_resolve(ctx, addr, out_buf, max_len):
                sym = symbol_resolver(addr)
                if sym is not None:
                    encoded = sym.encode('utf-8')
                    if len(encoded) < max_len:
                        ctypes.memmove(out_buf, encoded, len(encoded))
                        # Null terminate
                        ctypes.memset(out_buf + len(encoded), 0, 1)
                        return True
                return False
                
            self._last_callback = RESOLVE_CALLBACK(py_resolve)
            resolver_struct = PromSymbolResolver(None, self._last_callback)
            resolver_ptr = ctypes.pointer(resolver_struct)

        success = self.lib.prom_decode_and_format(
            self.decoder_ptr,
            buffer,
            len(code_bytes),
            address,
            syntax,
            resolver_ptr,
            out_str,
            256,
            ctypes.byref(out_inst)
        )
        
        if success:
            return {
                "text": out_str.value.decode('utf-8'),
                "length": out_inst.length,
                "address": out_inst.address
            }
        return None

if __name__ == "__main__":
    decoder = PrometheusDecoder()
    
    # [B8 01 00 00 00]
    code = b"\xB8\x01\x00\x00\x00"
    
    print("init: prom_py")
    result = decoder.decode(code, address=0x1000)
    print(f"[{hex(result['address'])}] {code[:result['length']].hex()} : {result['text']}")
    
    # Resolution target.
    def resolve(addr):
        if addr == 0x140001000:
            return "kernel32!VirtualAlloc"
        return None
        
    code_call = b"\xE8\xFB\x0F\x00\x40" # CALL rel32
    result = decoder.decode(code_call, address=0x100000000, symbol_resolver=resolve)
    print(f"[{hex(result['address'])}] {code_call[:result['length']].hex()} : {result['text']}")
