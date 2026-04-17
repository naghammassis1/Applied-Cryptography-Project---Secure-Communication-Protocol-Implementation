import socket
import json
import struct

from crypto_core import (
    rsa_generate_128, rsa_sign, rsa_verify,
    dh_private, dh_public, dh_shared,
    derive_session_key, signed_data,
    encrypt_message, decrypt_message
)

HOST = "127.0.0.1"
PORT = 5055

MY_ID = "1220149"      # Alice
PEER_ID = "1220168"    # Bob

# =============================
# networking helpers (TCP JSON)
# =============================
def send_json(conn, obj):
    data = json.dumps(obj).encode("utf-8")
    header = struct.pack("!I", len(data))
    conn.sendall(header + data)

def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf

def recv_json(conn):
    header = recv_exact(conn, 4)
    (length,) = struct.unpack("!I", header)
    data = recv_exact(conn, length)
    return json.loads(data.decode("utf-8"))


def main():
    # generate Alice RSA key pair
    my_rsa = rsa_generate_128()

    # connect to server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    print("Connected to server")

    # ---------------------------
    # Alice generates A and signs
    # ---------------------------
    a = dh_private()
    A = dh_public(a)
    sigA = rsa_sign(signed_data(MY_ID, PEER_ID, A), my_rsa)

    # send hello (A + signature + Alice public key)
    send_json(s, {
        "type": "Nagham",
        "sender_id": MY_ID,
        "A": str(A),
        "sig": str(sigA),
        "n": str(my_rsa.n),
        "e": str(my_rsa.e)
    })

    # ---------------------------
    # receive Bob response and verify
    # ---------------------------
    m2 = recv_json(s)
    if m2.get("type") != "Alzahra":
        raise ValueError("unexpected message type")

    bob_id = m2["sender_id"]
    B = int(m2["B"])
    sigB = int(m2["sig"])
    nB = int(m2["n"])
    eB = int(m2["e"])

    okB = rsa_verify(signed_data(bob_id, MY_ID, B), sigB, nB, eB)
    print("Bob signature valid?", okB)
    if not okB:
        raise RuntimeError("Bob signature invalid")

    # ---------------------------
    # derive session key
    # ---------------------------
    shared = dh_shared(B, a)
    session_key = derive_session_key(shared)
    print("Alice session key:", session_key.hex())

    # ---------------------------
    # send encrypted message (IV + CT)
    # ---------------------------
    msg = "hello over network (AES-CBC)"
    iv_hex, ct_hex = encrypt_message(msg, session_key)
    send_json(s, {"type": "data", "iv": iv_hex, "ct": ct_hex})

    # receive encrypted reply and decrypt
    reply = recv_json(s)
    back = decrypt_message(reply["iv"], reply["ct"], session_key)
    print("Decrypted reply:", back)

    s.close()

if __name__ == "__main__":
    main()