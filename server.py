#!/usr/bin/env python3
import itertools
import logging
import socket
import struct
import threading

import crypto

logger = logging.getLogger("nba2k10")

HOST = "0.0.0.0"
PORT = 1004

# Any 16 bytes work as the seed (client derives it from our handshake).
SEED = bytes.fromhex("00112233445566778899aabbccddeeff")
HANDSHAKE = crypto.bf_encrypt(SEED)  # 16 bytes sent first

_ctr = itertools.count()

MAGIC = b"\x10\x06"
DEFAULT_BODY = b"\x00\x00\x00\x00"
LOGIN_ACK = bytes.fromhex("1214010200000000")
ASSIGN_ID = 0x00000001  # id handed to the client for its ffffffff "assign me" queries


def build_response(mtype, req_body):
    opcode = req_body[1] if len(req_body) >= 2 else -1
    if mtype == 0x0002:  # login ack
        body = LOGIN_ACK
    elif opcode == 0x12:  # id query: assign id
        body = req_body.replace(b"\xff\xff\xff\xff", struct.pack(">I", ASSIGN_ID))
    elif opcode == 0x03:  # data chunk / finalize ack
        sub = req_body[2] if len(req_body) >= 3 else 0
        if sub == 0x07:
            # finalize reads a status u32 at body offset 8; MUST be 0 (success).
            body = bytes([0x00, 0x03, 0x07, 0, 0, 0, 0, 0]) + struct.pack(">III", 0, 0, 0)
        else:
            body = bytes([0x00, 0x03, sub]) + struct.pack(">I", 1)  # chunks: short-ack
    elif opcode == 0x11:  # leaderboard: echo
        body = req_body
    else:
        body = DEFAULT_BODY
    msg = MAGIC + struct.pack(">H", mtype) + body
    return struct.pack(">I", len(msg) + 4) + msg


def handle(conn, addr):
    n = next(_ctr)
    logger.info(f"connect #{n} {addr[0]}:{addr[1]}")
    try:
        conn.sendall(HANDSHAKE)  # 16-byte Blowfish-encrypted seed
        rx = crypto.LFG(SEED)  # decrypts client -> server
        tx = crypto.LFG(SEED)  # encrypts server -> client

        conn.settimeout(20.0)
        # request/response loop. Frame = [4B len][2B 1006][2B type][body]
        raw = b""
        dec = b""

        def need(k):
            nonlocal raw, dec
            while len(dec) < k:
                chunk = conn.recv(4096)
                if not chunk:
                    return False
                raw += chunk
                while len(dec) < len(raw):
                    dec += bytes([raw[len(dec)] ^ rx.next()])
            return True

        consumed = 0
        while True:
            if not need(consumed + 4):
                break
            mlen = struct.unpack(">I", dec[consumed : consumed + 4])[0]
            if not need(consumed + mlen):
                break
            msg = dec[consumed : consumed + mlen]
            consumed += mlen
            mtype = struct.unpack(">H", msg[6:8])[0] if mlen >= 8 else -1
            resp = build_response(mtype, msg[8:])
            conn.sendall(bytes([b ^ tx.next() for b in resp]))
    except socket.timeout:
        pass
    except Exception:
        logger.exception(f"#{n} error")
    finally:
        conn.close()


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(16)
    logger.info("NBA2K10 Draft Combine server listening on :1004")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
