# -*- coding: utf-8 -*-

import sys
from .util import bh2u

try:
    from blspy import BasicSchemeMPL, G1Element, G2Element, PrivateKey, PublicKey

    import_success = True
    load_libdashbls = False
except ImportError:
    import_success = False
    load_libdashbls = True


if load_libdashbls:
    import ctypes

    class KeyPair(ctypes.Structure):
        _fields_ = [
            ("privKey", ctypes.c_ubyte * 32),
            ("pubKey", ctypes.c_ubyte * 48),
        ]

    class Signature(ctypes.Structure):
        _fields_ = [
            ("data", ctypes.c_ubyte * 96),  # Signature is 96 bytes
        ]


    from ctypes import cdll, create_string_buffer, byref, c_bool

    if sys.platform == 'darwin':
        name = '/Users/pshenmic/WebstormProjects/electrum-dash/electrum_dash/libdashbls.dylib'
    elif sys.platform in ('windows', 'win32'):
        name = 'libdashbls-0.dll'
    else:
        name = 'libdashbls.so'

    # try:
    #     ldashbls = cdll.LoadLibrary(name)
    #
    #     ldashbls.bls_basic_verify.argtypes = [ctypes.c_char_p, ctypes.c_bool, ctypes.c_char_p, ctypes.c_char_p]
    #     ldashbls.bls_basic_verify.restype = ctypes.c_bool
    #
    #     ldashbls.bls_basic_keygen.argtypes = [ctypes.c_char_p]
    #     ldashbls.bls_basic_keygen.restype = KeyPair
    #
    #     ldashbls.bls_basic_sign.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
    #     ldashbls.bls_basic_sign.restype = Signature
    # except:
    #   load_libdashbls = False

    ldashbls = cdll.LoadLibrary(name)

    ldashbls.bls_basic_verify.argtypes = [ctypes.c_char_p, ctypes.c_bool, ctypes.c_char_p, ctypes.c_char_p]
    ldashbls.bls_basic_verify.restype = ctypes.c_bool

    ldashbls.bls_basic_keygen.argtypes = [ctypes.c_char_p]
    ldashbls.bls_basic_keygen.restype = KeyPair

    ldashbls.bls_basic_sign.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
    ldashbls.bls_basic_sign.restype = Signature

if load_libdashbls:

    class BasicSchemeMPL:
        def verify(g1element, message, g2element):
            return ldashbls.bls_basic_verify(g1element.bytes, g1element.isLegacy, g2element.bytes, message)

        def key_gen(seed: bytes):
            """
            Generates an object containing private and public keys,
            emulating get_g1 and __bytes__ methods.
            """
            # Call the native function that returns a KeyPair
            key_pair = ldashbls.bls_basic_keygen(seed)

            # Convert ctypes arrays to bytes
            privkey_bytes = bytes(key_pair.privKey)
            pubkey_bytes = bytes(key_pair.pubKey)

            # Dynamically create an object with the required methods
            return type(
                "PrivateKey",  # Type name (can be any string)
                (object,),  # Inherit from object
                {
                    "__bytes__": lambda self: privkey_bytes,  # Private key as bytes
                    "get_g1": lambda self: type(
                        "PublicKey",  # Type name for the public key
                        (object,),  # Inherit from object
                        {
                            "__bytes__": lambda self: pubkey_bytes  # Public key as bytes
                        }
                    )()  # Create an instance of the public key
                }
            )()  # Create an instance of the private key

        def sign(privkey, message: bytes):
            privkey_bytes = privkey.__bytes__()

            # Call the native function
            signature = ldashbls.bls_basic_sign(
                privkey_bytes,
                message,
                len(message)
            )

            # Convert the signature structure to bytes
            signature_bytes = bytes(signature.data)

            # Dynamically create an object representing the signature
            return type(
                "G2Element",  # Name of the type
                (object,),  # Base class
                {
                    "__bytes__": lambda self: signature_bytes  # Return signature as bytes
                }
            )()  # Create an instance

    class G1Element:
        bytes = b""
        isLegacy = False

        def __init__(self, bytes, isLegacy):
            self.bytes = bytes
            self.isLegacy = isLegacy

        def from_bytes(bytes, isLegacy):
            return G1Element(bytes, isLegacy)

    class G2Element:
        bytes = b""

        def __init__(self, bytes):
            self.bytes = bytes

        def from_bytes(bytes):
            return G2Element(bytes)


    class PrivateKey:
        def __init__(self, privkey_bytes: bytes):
            if len(privkey_bytes) != 32:
                raise ValueError("Private key must be 32 bytes")
            self._privkey = privkey_bytes

        @staticmethod
        def from_bytes(privkey_bytes: bytes):
            """
            Create a PrivateKey instance from bytes.
            """
            return PrivateKey(privkey_bytes)

        def __bytes__(self):
            """
            Return the private key as bytes.
            """
            return self._privkey

        def get_g1(self):
            """
            Placeholder for the public key generation logic.
            """
            raise NotImplementedError("get_g1 method is not implemented in the fallback PrivateKey class.")

if not import_success and not load_libdashbls:
    raise ImportError('Can not import blspy')
