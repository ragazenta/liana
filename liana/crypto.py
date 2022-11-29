import os
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519, ed25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)


def generate_ec256_privkey() -> bytes:
    privkey = ec.generate_private_key(ec.SECP256R1())
    return privkey.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def generate_x25519_privkey() -> bytes:
    privkey = x25519.X25519PrivateKey.generate()
    return privkey.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def generate_ed25519_privkey() -> bytes:
    privkey = ed25519.Ed25519PrivateKey.generate()
    return privkey.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def load_privkey(pem_privkey: bytes) -> ec.EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(pem_privkey, password=None)


def encrypt_ec256(data: bytes, pubkey: ec.EllipticCurvePublicKey) -> bytes:
    privkey = ec.generate_private_key(ec.SECP256R1())
    sharedkey = privkey.exchange(ec.ECDH(), pubkey)
    chacha = ChaCha20Poly1305(sharedkey)
    nonce = os.urandom(12)
    cipher = bytearray()
    cipher.extend(nonce)
    cipher.extend(chacha.encrypt(nonce, data, None))
    cipherpub = privkey.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )[27:152]
    return base64.b64encode(cipher) + cipherpub[:64] + cipherpub[65:]


def decrypt_ec256(cipher: bytes, privkey: ec.EllipticCurvePrivateKey) -> bytes:
    length = len(cipher)
    decoded = base64.b64decode(cipher[: (length - 124)])
    nonce = decoded[:12]
    cipherpub = cipher[(length - 124) :]
    pubkey = serialization.load_pem_public_key(
        b"-----BEGIN PUBLIC KEY-----\n"
        + cipherpub[:64]
        + b"\n"
        + cipherpub[64:]
        + b"\n"
        + b"-----END PUBLIC KEY-----\n"
    )
    sharedkey = privkey.exchange(ec.ECDH(), pubkey)

    chacha = ChaCha20Poly1305(sharedkey)
    return chacha.decrypt(nonce, decoded[12:], None)


def encrypt_x25519(data: bytes, pubkey: ec.EllipticCurvePublicKey) -> bytes:
    privkey = x25519.X25519PrivateKey.generate()
    sharedkey = privkey.exchange(pubkey)
    chacha = ChaCha20Poly1305(sharedkey)
    nonce = os.urandom(12)
    cipher = bytearray()
    cipher.extend(nonce)
    cipher.extend(chacha.encrypt(nonce, data, None))
    cipherpub = privkey.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )[27:87]
    return base64.b64encode(cipher) + cipherpub


def decrypt_x25519(cipher: bytes, privkey: ec.EllipticCurvePrivateKey) -> bytes:
    length = len(cipher)
    decoded = base64.b64decode(cipher[: (length - 60)])
    nonce = decoded[:12]
    cipherpub = cipher[(length - 60) :]
    pubkey = serialization.load_pem_public_key(
        b"-----BEGIN PUBLIC KEY-----\n"
        + cipherpub
        + b"\n"
        + b"-----END PUBLIC KEY-----\n"
    )
    sharedkey = privkey.exchange(pubkey)

    chacha = ChaCha20Poly1305(sharedkey)
    return chacha.decrypt(nonce, decoded[12:], None)
