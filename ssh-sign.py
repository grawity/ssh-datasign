#!/usr/bin/env python3
# v0.1
# (c) 2018 Mantas Mikulėnas <grawity@gmail.com>
# Released under the MIT License (https://spdx.org/licenses/MIT)
import binascii
import enum
import hashlib
import io
import os
import socket
import struct
import sys

def b64_encode(buf):
    return binascii.b2a_base64(buf, newline=False).decode()

class SshEndOfStream(Exception):
    pass

class SshReader(object):
    @classmethod
    def from_bytes(self, buf):
        return self(io.BytesIO(buf))

    def __init__(self, input_fh):
        if hasattr(input_fh, "makefile"):
            input_fh = input_fh.makefile("rb")
        self.input_fh = input_fh

    def read(self, *args):
        buf = self.input_fh.read(*args)
        if not buf:
            raise SshEndOfStream()
        return buf

    def read_byte(self):
        buf = self.read(1)
        val, = struct.unpack("!B", buf)
        return val

    def read_uint32(self):
        buf = self.read(4)
        val, = struct.unpack("!L", buf)
        return val

    def read_bool(self):
        buf = self.read(1)
        val, = struct.unpack("!?", buf)
        return val

    def read_string(self):
        length = self.read_uint32()
        buf = self.read(length)
        return buf

    def read_string_pkt(self):
        buf = self.read_string()
        return SshReader.from_bytes(buf)

    def read_struct(self, types):
        data = []
        for tchar in types:
            if tchar == "B":
                data.append(self.read_byte())
            elif tchar == "L":
                data.append(self.read_uint32())
            elif tchar == "b":
                data.append(self.read_string())
            elif tchar == "s":
                data.append(self.read_string().decode())
            else:
                raise ValueError("unknown type %r" % (tchar))
        return data

    def read_message(self, types):
        pkt = self.read_string_pkt()
        return pkt.read_struct(types)

class SshWriter(object):
    def __init__(self, output_fh):
        if hasattr(output_fh, "makefile"):
            output_fh = output_fh.makefile("wb")
        self.output_fh = output_fh

    def write(self, *args, flush=False):
        ret = self.output_fh.write(*args)
        if ret and flush:
            ret = self.output_fh.flush()
        return ret

    def write_struct(self, types, *data, length_prefix=False):
        fmt = "!L" if length_prefix else "!"
        packed = [0] if length_prefix else []
        for i, _ in enumerate(types):
            if types[i] == "B":
                # (uint8) value
                fmt += "B"
                packed.append(int(data[i]))
            elif types[i] == "L":
                # (uint32) value
                fmt += "L"
                packed.append(int(data[i]))
            elif types[i] == "b":
                # (uint32) length, (buffer[]) value
                buf = data[i]
                fmt += "L%ds" % len(buf)
                packed.append(len(buf))
                packed.append(bytes(buf))
            elif types[i] == "s":
                buf = data[i].encode()
                fmt += "L%ds" % len(buf)
                packed.append(len(buf))
                packed.append(bytes(buf))
            else:
                raise ValueError("unknown type %r of %r" % (types[i], data[i]))
        if length_prefix:
            packed[0] = struct.calcsize(fmt) - 4
        buf = struct.pack(fmt, *packed)
        self.write(buf, flush=True)

    def write_message(self, types, *data):
        return self.write_struct(types, *data, length_prefix=True)

class SshStream(SshReader, SshWriter):
    def __init__(self, input_fh, output_fh=None):
        SshReader.__init__(self, input_fh)
        SshWriter.__init__(self, output_fh or input_fh)

class SshAgentCommand(enum.IntEnum):
    REQUEST_IDENTITIES      = 11
    SIGN_REQUEST            = 13
    ADD_IDENTITY            = 17
    REMOVE_IDENTITY         = 18
    REMOVE_ALL_IDENTITIES   = 19

class SshAgentReply(enum.IntEnum):
    FAILURE                 = 5
    SUCCESS                 = 6
    IDENTITIES_ANSWER       = 12
    SIGN_RESPONSE           = 14

class SignRequestFlags(enum.IntFlag):
    RSA_SHA2_256            = 1 << 1
    RSA_SHA2_512            = 1 << 2

class SshAgentKey(object):
    def __init__(self, agent, keyblob, comment):
        self.agent = agent
        self.keyblob = keyblob
        self.comment = comment

    def fprint_md5_hex(self):
        dgst = hashlib.md5(self.keyblob).digest()
        dgst = ":".join(["%02x" % x for x in dgst])
        return "MD5:" + dgst

    def fprint_sha256_base64(self):
        dgst = hashlib.sha256(self.keyblob).digest()
        dgst = binascii.b2a_base64(dgst, newline=False).decode().rstrip("=")
        return "SHA256:" + dgst

    def sign_data(self, buf, flags=0):
        return self.agent.sign_data(buf, self.keyblob, flags)

class SshAgentConnection(object):
    def __init__(self, path=None):
        if not path:
            path = os.environ["SSH_AUTH_SOCK"]
        self.path = path
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.path)
        self.stream = SshStream(self.sock)

    def list_keys(self):
        self.stream.write_message("B", SshAgentCommand.REQUEST_IDENTITIES)
        pkt = self.stream.read_string_pkt()
        result = SshAgentReply(pkt.read_byte())
        if result != SshAgentReply.IDENTITIES_ANSWER:
            raise IOError("expected IDENTITIES_ANSWER, got %r" % result)
        nkeys = pkt.read_uint32()
        keys = []
        for i in range(nkeys):
            (keyblob, comment) = pkt.read_struct("bb")
            key = SshAgentKey(self, keyblob, comment)
            keys.append(key)
        return keys

    def get_key_by_fprint(self, fpr):
        keys = self.list_keys()
        for key in keys:
            if fpr in {key.fprint_sha256_base64(), key.fprint_md5_hex()}:
                return key
        raise KeyError("no key with fingerprint %r found in agent" % fpr)

    def sign_data(self, buf, keyblob, flags=0):
        self.stream.write_message("BbbL", SshAgentCommand.SIGN_REQUEST,
                                  keyblob, buf, flags)
        pkt = self.stream.read_string_pkt()
        result = SshAgentReply(pkt.read_byte())
        if result != SshAgentReply.SIGN_RESPONSE:
            raise IOError("expected SIGN_RESPONSE, got %r" % result)
        (sigalgo, sigvalue) = pkt.read_message("sb")
        return sigalgo, sigvalue

fpr = sys.argv[1]
data = sys.argv[2].encode()

agent = SshAgentConnection()
key = agent.get_key_by_fprint(fpr)
flags = 0
flags = SignRequestFlags.RSA_SHA2_256
algo, rawsig = key.sign_data(data, flags)

# Signature formats:
# https://tools.ietf.org/html/rfc4253#section-6.6
# https://tools.ietf.org/html/draft-ietf-curdle-rsa-sha2-00
# https://tools.ietf.org/html/draft-irtf-cfrg-eddsa-05
# https://tools.ietf.org/html/draft-ietf-curdle-ssh-ed25519-00

print("Signed using %s" % algo)
if algo in {b"ssh-rsa", b"rsa-sha2-256", b"rsa-sha2-512"}:
    # compatible with OpenSSL; RSASSA-PKCS1-v1_5 is used
    print("Raw signature:", b64_encode(rawsig))
else:
    raise ValueError("signatures of %r not implemented" % algo)
