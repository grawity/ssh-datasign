#!/usr/bin/env python3
# v0.1
# (c) 2018 Mantas Mikulėnas <grawity@gmail.com>
# Released under the MIT License (https://spdx.org/licenses/MIT)
import base64
import binascii
import enum
import hashlib
import io
from nullroute.io import SshBinaryReader, SshBinaryWriter
import os
from pprint import pprint
import socket
import struct
import sys
from types import SimpleNamespace

def b64_encode(buf):
    return binascii.b2a_base64(buf, newline=False).decode()

class SshEndOfStream(Exception):
    pass

class UnsupportedKeyType(Exception):
    pass

class UnsupportedSignatureType(Exception):
    pass

class UnsupportedVersion(Exception):
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

    def read_mpint(self):
        buf = self.read_string()
        return int.from_bytes(buf, byteorder="big", signed=False)

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
                fmt += "B"
                packed.append(int(data[i]))
            elif types[i] == "L":
                fmt += "L"
                packed.append(int(data[i]))
            elif types[i] == "M":
                nd, nm = divmod(data[i].bit_length(), 8)
                buf = data[i].to_bytes(nd + int(nm > 0), byteorder="big")
                fmt += "L%ds" % len(buf)
                packed.append(len(buf))
                packed.append(bytes(buf))
            elif types[i] == "b":
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
    def __init__(self, agent, keyblob, comment=None):
        self.agent = agent
        self.keyblob = keyblob
        self.comment = comment

        keydata = ssh_parse_pubkey(self.keyblob, algoonly=True)
        self.keyalgo = keydata["algo"]

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
            keyblob = pkt.read_string()
            comment = pkt.read_string().decode("utf-8")
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
        sig = pkt.read_string()
        return sig

# Signature formats:
# https://tools.ietf.org/html/rfc4253#section-6.6
# https://tools.ietf.org/html/draft-ietf-curdle-rsa-sha2-00
# https://tools.ietf.org/html/draft-irtf-cfrg-eddsa-05
# https://tools.ietf.org/html/draft-ietf-curdle-ssh-ed25519-00

def ssh_parse_pubkey(buf, algoonly=False):
    pkt = SshReader.from_bytes(buf)
    algo = pkt.read_string().decode()
    data = {"algo": algo}
    if algoonly:
        return data
    elif algo == "ssh-rsa":
        # https://tools.ietf.org/html/rfc4253#section-6.6
        data["e"] = pkt.read_mpint()
        data["n"] = pkt.read_mpint()
    elif algo == "ssh-dss":
        # https://tools.ietf.org/html/rfc4253#section-6.6
        data["p"] = pkt.read_mpint()
        data["q"] = pkt.read_mpint()
        data["g"] = pkt.read_mpint()
        data["y"] = pkt.read_mpint()
    elif algo in {"ssh-ed25519", "ssh-ed448"}:
        # https://tools.ietf.org/html/draft-ietf-curdle-ssh-ed25519-ed448-00#section-4
        data["key"] = pkt.read_string()
    else:
        raise UnsupportedKeyType(algo)
    return data

def ssh_parse_signature(buf, algoonly=False):
    pkt = SshReader.from_bytes(buf)
    algo = pkt.read_string().decode()
    data = {"algo": algo}
    if algoonly:
        return data
    elif algo in {"ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"}:
        # https://tools.ietf.org/html/rfc4253#section-6.6
        data["s"] = pkt.read_string()
    elif algo == "ssh-dss":
        # https://tools.ietf.org/html/rfc4253#section-6.6
        data["e"] = pkt.read_mpint()
        data["n"] = pkt.read_mpint()
    elif algo in {"ssh-ed25519", "ssh-ed448"}:
        # https://tools.ietf.org/html/draft-ietf-curdle-ssh-ed25519-ed448-00#section-4
        data["sig"] = pkt.read_string()
    else:
        raise UnsupportedSignatureType(algo)
    return data

def ssh_format_sshsig(pubkey, namespace, sig_algo, signature):
    # PROTOCOL.sshsig
    buf = io.BytesIO()
    pkt = SshBinaryWriter(buf)
    pkt.write(b"SSHSIG")
    pkt.write_uint32(0x01)
    pkt.write_string(pubkey)
    pkt.write_string(namespace)
    pkt.write_string(b"")
    pkt.write_string(sig_algo.encode())
    pkt.write_string(signature)
    return buf.getvalue()

def ssh_parse_sshsig(buf):
    pkg = SshReader.from_bytes(buf)
    magic = pkt.read(6)
    if magic != b"SSHSIG":
        raise ValueError("magic preamble not found")
    version = pkt.read_uint32()
    data = {"version": version}
    if version == 0x01:
        data["publickey"] = pkt.read_string()
        data["namespace"] = pkt.read_string()
        data["reserved"] = pkt.read_string()
        data["sig_algo"] = pkt.read_string()
        data["signature"] = pkt.read_string()
    else:
        raise UnsupportedVersion(version)
    return data

def ssh_enarmor_sshsig(buf):
    # TODO: wrap to 76
    buf = base64.encodebytes(buf).decode()
    return "-----BEGIN SSH SIGNATURE-----\n" + buf + "-----END SSH SIGNATURE-----\n"

sigalgo_to_keyalgo = {
    "rsa-sha2-256":     "ssh-rsa",
    "rsa-sha2-512":     "ssh-rsa",
}

sigalgo_to_digest = {
    "ssh-rsa":          "sha1",
    "rsa-sha2-256":     "sha256",
    "rsa-sha2-512":     "sha512",
}

def cry_import_pubkey(pubkey_data):
    key_algo = pubkey_data["algo"]
    if key_algo == "ssh-rsa":
        from Crypto.PublicKey import RSA
        return RSA.construct((pubkey_data["n"],
                              pubkey_data["e"]))
    else:
        raise UnsupportedKeyType(key_algo)

def cry_verify_signature(buf, pubkey_data, signature_data):
    key_algo = pubkey_data["algo"]
    sig_algo = signature_data["algo"]
    if sigalgo_to_keyalgo.get(sig_algo, sig_algo) != key_algo:
        raise UnsupportedKeyType(key_algo)
    if key_algo == "ssh-rsa":
        from Crypto.Hash import SHA, SHA256, SHA512
        from Crypto.Signature import PKCS1_v1_5
        if sig_algo == "ssh-rsa":
            dg = SHA.new(buf)
        elif sig_algo == "rsa-sha2-256":
            dg = SHA256.new(buf)
        elif sig_algo == "rsa-sha2-512":
            dg = SHA512.new(buf)
        else:
            raise UnsupportedSignatureType(sig_algo)
        pk = cry_import_pubkey(pubkey_data)
        sg = PKCS1_v1_5.new(pk)
        return sg.verify(dg, signature_data["s"])
    elif key_algo == "ssh-ed25519":
        import ed25519
        pk = ed25519.VerifyingKey(pubkey_data["key"])
        try:
            pk.verify(signature_data["sig"], buf)
            return True
        except ed25519.BadSignatureError:
            return False
    else:
        raise UnsupportedKeyType(key_algo)

cmd, *rest = sys.argv[1:]

if cmd == "sign":
    fprint, data = rest
    data = data.encode()

    agent = SshAgentConnection()
    agentkey = agent.get_key_by_fprint(fprint)

    flags = 0
    if agentkey.keyalgo == "ssh-rsa":
    	flags |= SignRequestFlags.RSA_SHA2_256
    sigblob = agentkey.sign_data(data, flags)

    keydata = ssh_parse_pubkey(agentkey.keyblob)
    sigdata = ssh_parse_signature(sigblob)
    print("Signed using %s" % sigdata["algo"])
    pprint(keydata)
    pprint(sigdata)

    tmp = ssh_format_sshsig(agentkey.keyblob, b"", sigdata["algo"], sigblob)
    tmp = ssh_enarmor_sshsig(tmp)
    print(tmp)

    print("verify:", cry_verify_signature(data, keydata, sigdata))

    if sigdata["algo"] in {"ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"}:
        # compatible with OpenSSL; RSASSA-PKCS1-v1_5 is used
        print("Raw signature:", b64_encode(sigdata["s"]))
    else:
        pass
        #raise ValueError("signatures of %r not supported" % sigdata["algo"])

elif cmd == "verify":
    pass
