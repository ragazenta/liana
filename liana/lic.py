import jwt


ALGORITHMS = {
    "EC256": "ES256",
    "Ed25519": "EdDSA",
}


def generate(payload, signkey, algorithm) -> bytes:
    if algorithm not in ALGORITHMS:
        return "invalid_algorithm"

    encoded = jwt.encode(payload, signkey, ALGORITHMS[algorithm])
    array = bytearray(b"-----BEGIN LICENSE-----\n")
    for s in (encoded[i : i + 64] for i in range(0, len(encoded), 64)):
        array.extend(s.encode("ascii"))
        array.append(0x0A)
    array.extend(b"-----END LICENSE-----\n")
    return bytes(array)
