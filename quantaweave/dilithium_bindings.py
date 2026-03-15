import ctypes
import os

# Path to the compiled lattice signature shared library (update as needed)
LIB_PATH = os.path.join(os.path.dirname(__file__), '../../lattice_sig/ref/lattice_sig_ref.dll')

class LatticeSignatureC:
    def __init__(self, lib_path=LIB_PATH):
        self.lib = ctypes.cdll.LoadLibrary(lib_path)
        # Set argument and return types for the C API
        self.lib.crypto_sign_keypair.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self.lib.crypto_sign_keypair.restype = ctypes.c_int
        self.lib.crypto_sign.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
        self.lib.crypto_sign.restype = ctypes.c_int
        self.lib.crypto_sign_open.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
        self.lib.crypto_sign_open.restype = ctypes.c_int

    def keypair(self):
        # Sizes from params.h (update as needed)
        CRYPTO_PUBLICKEYBYTES = 1312
        CRYPTO_SECRETKEYBYTES = 2528
        pk = (ctypes.c_ubyte * CRYPTO_PUBLICKEYBYTES)()
        sk = (ctypes.c_ubyte * CRYPTO_SECRETKEYBYTES)()
        res = self.lib.crypto_sign_keypair(pk, sk)
        if res != 0:
            raise RuntimeError('Lattice signature keypair generation failed')
        return bytes(pk), bytes(sk)

    def sign(self, message: bytes, sk: bytes, ctx: bytes = b'test_lattice_sig'):
        CRYPTO_BYTES = 2420
        sm = (ctypes.c_ubyte * (len(message) + CRYPTO_BYTES))()
        smlen = ctypes.c_size_t()
        m = (ctypes.c_ubyte * len(message)).from_buffer_copy(message)
        sk_buf = (ctypes.c_ubyte * len(sk)).from_buffer_copy(sk)
        ctx_buf = (ctypes.c_ubyte * len(ctx)).from_buffer_copy(ctx)
        res = self.lib.crypto_sign(sm, ctypes.byref(smlen), m, len(message), ctx_buf, len(ctx), sk_buf)
        if res != 0:
            raise RuntimeError('Lattice signature sign failed')
        return bytes(sm)[:smlen.value]

    def verify(self, signed: bytes, pk: bytes, ctx: bytes = b'test_lattice_sig'):
        m = (ctypes.c_ubyte * len(signed))()
        mlen = ctypes.c_size_t()
        sm = (ctypes.c_ubyte * len(signed)).from_buffer_copy(signed)
        pk_buf = (ctypes.c_ubyte * len(pk)).from_buffer_copy(pk)
        ctx_buf = (ctypes.c_ubyte * len(ctx)).from_buffer_copy(ctx)
        res = self.lib.crypto_sign_open(m, ctypes.byref(mlen), sm, len(signed), ctx_buf, len(ctx), pk_buf)
        return res == 0
