import jwt


ALGORITHMS = {
    "EC256": "ES256",
    "Ed25519": "EdDSA",
}


def generate(payload, signkey: bytes, algorithm: str) -> bytes:
    if algorithm not in ALGORITHMS:
        return "invalid_algorithm"

    encoded = jwt.encode(payload, signkey, ALGORITHMS[algorithm])
    array = bytearray(b"-----BEGIN LICENSE-----\n")
    for s in (encoded[i : i + 64] for i in range(0, len(encoded), 64)):
        array.extend(s.encode("ascii"))
        array.append(0x0A)
    array.extend(b"-----END LICENSE-----\n")
    return bytes(array)


def decode(content: str, lickey: bytes, algorithm: str) -> dict:
    if algorithm not in ALGORITHMS:
        return {
            "invalid": "invalid_algorithm",
        }

    lines = content.encode("ascii").split(b"\n")
    token = b"".join(lines[1 : len(lines) - 2])
    try:
        return jwt.decode(token, lickey.encode("ascii"), ALGORITHMS[algorithm])
    except Exception as e:
        return {
            "error": str(e),
        }
