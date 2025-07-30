import hashlib
import py_ecc as py_ecc

from py_ecc.bls.point_compression import compress_G1
from py_ecc.bls.typing import G1Compressed
from py_ecc.optimized_bls12_381.optimized_curve import (
    G1, add, curve_order, eq, multiply, neg
)


# DST per RFC-9380 for G1 with SHA256, SSWU and random oracle
DST = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_"

DOMAIN_SEPARATOR = b"ETHEREUM_VRF_V1"


def keccak256(msg: bytes) -> bytes:
    return hashlib.new("sha3_256", msg).digest()


def scalar_to_string(n: int):
    return "0x" + n.to_bytes(32, "little").hex()


def point_to_string(value: G1Compressed):
    return "0x" + value.to_bytes(48, "little").hex()


def hash_to_scalar(msg: bytes):
    lo = keccak256(msg + bytes([1]))
    hi = keccak256(msg + bytes([2]))
    le_bytes = lo + hi
    return int.from_bytes(le_bytes, "little") % curve_order


def hash_to_curve(msg: bytes):
    return py_ecc.bls.hash_to_curve.hash_to_G1(msg, DST, hashlib.sha3_256)


def test_case(private_key: int, nonce: int, seed: bytes):
    print("--------------------------------------------------------------------------------")
    print(f"private key: {scalar_to_string(private_key)}")

    public_key = multiply(G1, private_key)
    print(f"public key: {point_to_string(compress_G1(public_key))}")

    print(f"nonce: {scalar_to_string(nonce)}")

    hash = hash_to_curve(seed)
    print(f"hash: {point_to_string(compress_G1(hash))}")

    gamma = multiply(hash, private_key)
    print(f"gamma: {point_to_string(compress_G1(gamma))}")

    u = multiply(G1, nonce)
    print(f"U: {point_to_string(compress_G1(u))}")

    v = multiply(hash, nonce)
    print(f"V: {point_to_string(compress_G1(v))}")

    challenge = hash_to_scalar(
        compress_G1(public_key).to_bytes(48, "little") +
        compress_G1(hash).to_bytes(48, "little") +
        compress_G1(gamma).to_bytes(48, "little") +
        compress_G1(u).to_bytes(48, "little") +
        compress_G1(v).to_bytes(48, "little")
    )
    print(f"challenge: {scalar_to_string(challenge)}")

    signature = (nonce + challenge * private_key) % curve_order
    print(f"signature: {scalar_to_string(signature)}")

    u_prime = add(multiply(G1, signature), neg(
        multiply(public_key, challenge)))
    assert eq(u, u_prime)
    print(f"U': {point_to_string(compress_G1(u_prime))}")

    v_prime = add(multiply(hash, signature), neg(
        multiply(gamma, challenge)))
    assert eq(v, v_prime)
    print(f"V': {point_to_string(compress_G1(v_prime))}")


test_case(
    private_key=hash_to_scalar(b"SATOR AREPO TENET OPERA ROTAS"),
    nonce=hash_to_scalar(b"IBAM FORTE VIA SACRA"),
    seed=b"LOREM IPSUM DOLOR SIT AMET",
)

test_case(
    private_key=hash_to_scalar(b"LOREM IPSUM DOLOR SIT AMET"),
    nonce=hash_to_scalar(b"SIC APOLLO ME SERVAVIT"),
    seed=b"SATOR AREPO TENET OPERA ROTAS",
)

print("--------------------------------------------------------------------------------")
