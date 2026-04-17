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

MY_ID = "1220168"      # Bob
PEER_ID = "1220149"    # Alice

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
    # generate Bob RSA key pair
    my_rsa = rsa_generate_128()

    # start server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"Server listening on {HOST}:{PORT}")

    conn, addr = s.accept()
    print("Client connected:", addr)

    # ---------------------------
    # receive Alice hello
    # ---------------------------
    m1 = recv_json(conn)
    if m1.get("type") != "Nagham":
        raise ValueError("unexpected message type")

    alice_id = m1["sender_id"]
    A = int(m1["A"])
    sigA = int(m1["sig"])
    nA = int(m1["n"])
    eA = int(m1["e"])

    # verify Alice signature on her DH value
    okA = rsa_verify(signed_data(alice_id, MY_ID, A), sigA, nA, eA)
    print("Alice signature valid?", okA)
    if not okA:
        raise RuntimeError("Alice signature invalid")

    # ---------------------------
    # Bob generates B and signs
    # ---------------------------
    b = dh_private()
    B = dh_public(b)
    sigB = rsa_sign(signed_data(MY_ID, alice_id, B), my_rsa)

    # send Bob response (B + signature + Bob public key)
    send_json(conn, {
        "type": "Alzahra",
        "sender_id": MY_ID,
        "B": str(B),
        "sig": str(sigB),
        "n": str(my_rsa.n),
        "e": str(my_rsa.e)
    })

    # ---------------------------
    # derive session key
    # ---------------------------
    shared = dh_shared(A, b)
    session_key = derive_session_key(shared)
    print("Bob session key:", session_key.hex())

    # ---------------------------
    # receive encrypted msg (IV + CT) and decrypt
    # ---------------------------
    m3 = recv_json(conn)
    if m3.get("type") != "data":
        raise ValueError("expected encrypted data")

    iv_hex = m3["iv"]
    ct_hex = m3["ct"]

    plaintext = decrypt_message(iv_hex, ct_hex, session_key)
    print("Decrypted from client:", plaintext)

    # reply encrypted
    reply_text = "received ok"
    iv2, ct2 = encrypt_message(reply_text, session_key)
    send_json(conn, {"type": "data", "iv": iv2, "ct": ct2})

    conn.close()
    s.close()

if __name__ == "__main__":
    main()