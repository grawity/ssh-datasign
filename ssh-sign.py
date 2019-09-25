#!/usr/bin/env python3
# v0.1
# (c) 2018 Mantas Mikulėnas <grawity@gmail.com>
# Released under the MIT License (https://spdx.org/licenses/MIT)
import argparse
import binascii
import enum
import hashlib
import io
from nullroute.core import Core
import os
from pprint import pprint
import socket
import struct
import sys

def b64_encode(buf):
    return binascii.b2a_base64(buf, newline=False).decode()

def chunk(vec, size):
    for i in range(0, len(vec), size):
        yield vec[i:i+size]

class SshEndOfStream(Exception):
    pass

class UnsupportedKeyType(Exception):
    pass

class UnsupportedSignatureType(Exception):
    pass

class UnsupportedHashType(Exception):
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

    def read(self, length=None):
        buf = self.input_fh.read(length)
        if (not buf) and (length != None) and (length != 0):
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

    def flush(self):
        return self.output_fh.flush()

    def write_byte(self, val):
        buf = struct.pack("!B", val)
        return self.write(buf)

    def write_uint32(self, val):
        buf = struct.pack("!L", val)
        return self.write(buf)

    def write_bool(self, val):
        buf = struct.pack("!?", val)
        return self.write(buf)

    def write_string(self, val):
        buf = struct.pack("!L", len(val)) + val
        return self.write(buf)

    def write_mpint(self, val):
        length = val.bit_length()
        if length & 0xFF:
            length |= 0xFF
            length += 1
        length >>= 8
        Core.debug("mpint %r length %r", val, length)
        buf = val.to_bytes(length, "big", signed=False)
        return self.write_string(buf)

    def write_struct(self, items, *, length_prefix=False):
        fmt = "!L" if length_prefix else "!"
        packed = [0] if length_prefix else []
        for t, v in items:
            if t == "byte":
                fmt += "B"
                packed.append(int(v))
            elif t == "uint32":
                fmt += "L"
                packed.append(int(v))
            elif t == "mpint":
                nd, nm = divmod(v.bit_length(), 8)
                buf = v.to_bytes(nd + int(nm > 0), byteorder="big")
                fmt += "L%ds" % len(buf)
                packed.append(len(buf))
                packed.append(buf)
            elif t == "string":
                buf = bytes(v)
                fmt += "L%ds" % len(buf)
                packed.append(len(buf))
                packed.append(buf)
            else:
                raise ValueError("unknown type %r of %r" % (t, v))
        if length_prefix:
            packed[0] = struct.calcsize(fmt) - 4
        buf = struct.pack(fmt, *packed)
        self.write(buf, flush=True)

    def write_message(self, items):
        return self.write_struct(items, length_prefix=True)

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

        keydata = ssh_parse_publickey(self.keyblob, algoonly=True)
        self.keyalgo = keydata["algo"]

    def publickey_base64(self, with_type=False):
        buf = binascii.b2a_base64(self.keyblob, newline=False).decode()
        if with_type:
            return self.keyalgo + " " + buf
        else:
            return buf

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
        self.stream.write_message([("byte", SshAgentCommand.REQUEST_IDENTITIES)])
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
        self.stream.write_message([("byte", SshAgentCommand.SIGN_REQUEST),
                                   ("string", keyblob),
                                   ("string", buf),
                                   ("uint32", flags)])
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

def ssh_parse_publickey(buf, algoonly=False):
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
    elif algo.startswith("ecdsa-sha2-"):
        # https://tools.ietf.org/html/rfc5656#section-3.1
        data["curve"] = pkt.read_string()
        data["Q"] = pkt.read_string()
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
    elif algo.startswith("ecdsa-sha2-"):
        # https://tools.ietf.org/html/rfc5656#section-3.1.2
        #data["sig"] = pkt.read_string()
        sigpkt = pkt.read_string_pkt()
        data["r"] = sigpkt.read_mpint()
        data["s"] = sigpkt.read_mpint()
    else:
        raise UnsupportedSignatureType(algo)
    return data

def ssh_format_sshsigdata(namespace, hash_algo, hash):
    pkt = SshWriter(io.BytesIO())
    pkt.write(b"SSHSIG")
    pkt.write_string(namespace)
    pkt.write_string(b"")
    pkt.write_string(hash_algo.encode())
    pkt.write(hash)
    return pkt.output_fh.getvalue()

def ssh_parse_sshsigdata(buf):
    pkt = SshReader.from_bytes(buf)
    magic = pkt.read(6)
    if magic != b"SSHSIG":
        raise ValueError("magic preamble not found")
    data = {}
    data["namespace"] = pkt.read_string()
    data["reserved"] = pkt.read_string()
    data["hash_algo"] = pkt.read_string()
    data["hash"] = pkt.read()
    return data

def ssh_format_sshsig(pubkey, namespace, sig_algo, signature):
    # PROTOCOL.sshsig
    pkt = SshWriter(io.BytesIO())
    pkt.write(b"SSHSIG")
    pkt.write_uint32(0x01)
    pkt.write_string(pubkey)
    pkt.write_string(namespace)
    pkt.write_string(b"")
    pkt.write_string(sig_algo.encode())
    pkt.write_string(signature)
    return pkt.output_fh.getvalue()

def ssh_parse_sshsig(buf):
    pkt = SshReader.from_bytes(buf)
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
    buf = b64_encode(buf)
    buf = "\n".join([
            "-----BEGIN SSH SIGNATURE-----",
            *chunk(buf, 76),
            "-----END SSH SIGNATURE-----",
          ])
    return buf + "\n"

def ssh_dearmor_sshsig(buf):
    acc = ""
    match = False
    # TODO: stricter format check
    for line in buf.splitlines():
        if line == "-----BEGIN SSH SIGNATURE-----":
            match = True
        elif line == "-----END SSH SIGNATURE-----":
            break
        elif line and match:
            acc += line
    return binascii.a2b_base64(acc)

sigalgo_to_keyalgo = {
    "rsa-sha2-256":     "ssh-rsa",
    "rsa-sha2-512":     "ssh-rsa",
}

sigalgo_to_digest = {
    "ssh-rsa":          "sha1",
    "rsa-sha2-256":     "sha256",
    "rsa-sha2-512":     "sha512",
}

def hash_data(hash_algo, data):
    if hash_algo in {"sha1", "sha256", "sha512"}:
        return hashlib.new(hash_algo, data).digest()
    else:
        raise UnsupportedHashType(hash_algo)

def cry_verify_signature(buf, pubkey_data, signature_data):
    key_algo = pubkey_data["algo"]
    sig_algo = signature_data["algo"]
    if sigalgo_to_keyalgo.get(sig_algo, sig_algo) != key_algo:
        raise UnsupportedKeyType(key_algo)
    if key_algo == "ssh-rsa":
        from Crypto.Hash import SHA, SHA256, SHA512
        from Crypto.PublicKey import RSA
        from Crypto.Signature import PKCS1_v1_5
        if sig_algo == "ssh-rsa":
            dg = SHA.new(buf)
        elif sig_algo == "rsa-sha2-256":
            dg = SHA256.new(buf)
        elif sig_algo == "rsa-sha2-512":
            dg = SHA512.new(buf)
        else:
            raise UnsupportedSignatureType(sig_algo)
        pk = RSA.construct((pubkey_data["n"],
                            pubkey_data["e"]))
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
    elif key_algo.startswith("ecdsa-sha2-"):
        import ecdsa
        curves = {
            "ecdsa-sha2-nistp256": ecdsa.NIST256p,
            "ecdsa-sha2-nistp384": ecdsa.NIST384p,
            "ecdsa-sha2-nistp521": ecdsa.NIST521p,
        }
        digests = {
            # https://tools.ietf.org/html/rfc5656#section-6.2.1
            "ecdsa-sha2-nistp256": hashlib.sha256,
            "ecdsa-sha2-nistp384": hashlib.sha384,
            "ecdsa-sha2-nistp521": hashlib.sha512,
        }
        if pubkey_data["Q"][0] == 0x04:
            # complete point
            pk = ecdsa.VerifyingKey.from_string(pubkey_data["Q"][1:],
                                                curve=curves[key_algo],
                                                hashfunc=digests[key_algo])
        else:
            # probably compressed point?
            raise UnsupportedKeyType("%s{B0=%02x}" % (key_algo, pubkey_data["Q"][0]))
        try:
            pk.verify(signature_data, buf,
                      sigdecode=lambda sig, order: (sig["r"], sig["s"]))
            return True
        except ecdsa.BadSignatureError:
            return False
    else:
        raise UnsupportedKeyType(key_algo)

cmd, *rest = sys.argv[1:]

if cmd == "sign":
    _ap = argparse.ArgumentParser()
    _ap.add_argument("--fingerprint",
                     help="Key fingerprint in 'MD5:<hex>' or 'SHA256:<b64>' format")
    _ap.add_argument("--input-hexdata")
    _ap.add_argument("--input-string")
    _ap.add_argument("--test-verify", action="store_true")
    _ap.add_argument("--namespace")
    args = _ap.parse_args(rest)

    if not args.fingerprint:
        Core.die("signing key (--fingerprint) not specified")

    if args.input_hexdata:
        data = binascii.unhexlify(args.input_hexdata)
    elif args.input_string:
        data = args.input_string.encode()
    else:
        Core.die("input data not specified")

    namespace = (args.namespace or "").encode()

    # Format the inner packet that will be signed.

    hash_algo = "sha512"
    sshsigblob = ssh_format_sshsigdata(namespace,
                                       hash_algo,
                                       hash_data(hash_algo, data))

    # Sign the packet.

    agent = SshAgentConnection()
    agentkey = agent.get_key_by_fprint(args.fingerprint)

    flags = 0
    if agentkey.keyalgo == "ssh-rsa":
    	flags |= SignRequestFlags.RSA_SHA2_256

    sigblob = agentkey.sign_data(sshsigblob, flags)

    Core.trace("raw signature blob: %r", sigblob)

    # Show information.

    keydata = ssh_parse_publickey(agentkey.keyblob)
    sigdata = ssh_parse_signature(sigblob)
    Core.trace("parsed publickey blob: %r", keydata)
    Core.trace("parsed signature blob: %r", sigdata)

    sig_algo = sigdata["algo"]
    sig_algo = hash_algo
    Core.info("Signed using %s" % sig_algo)

    tmp = ssh_format_sshsig(agentkey.keyblob, namespace, sig_algo, sigblob)
    Core.trace("formatted sshsig packet: %r", tmp)
    Core.trace("=> %r", ssh_parse_sshsig(tmp))
    tmp = ssh_enarmor_sshsig(tmp)
    print(tmp)

    if args.test_verify:
        print("verify:", cry_verify_signature(data, keydata, sigdata))

        if sigdata["algo"] in {"ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"}:
            # compatible with OpenSSL; RSASSA-PKCS1-v1_5 is used
            print("Raw signature:", b64_encode(sigdata["s"]))
        else:
            pass
            #raise ValueError("signatures of %r not supported" % sigdata["algo"])

elif cmd == "verify":
    _ap = argparse.ArgumentParser()
    _ap.add_argument("--fingerprint",
                     help="Key fingerprint in 'MD5:<hex>' or 'SHA256:<b64>' format")
    _ap.add_argument("--publickey")
    _ap.add_argument("--input-hexdata")
    _ap.add_argument("--input-string")
    _ap.add_argument("--signature-string")
    _ap.add_argument("--namespace")
    args = _ap.parse_args(rest)

    if args.input_hexdata:
        data = binascii.unhexlify(args.input_hexdata)
    elif args.input_string:
        data = args.input_string.encode()
    else:
        Core.die("input data not specified")

    if args.signature_string:
        sshsigbuf = args.signature_string
    else:
        sshsigbuf = sys.stdin.read()

    namespace = (args.namespace or "").encode()

    sshsigbuf = ssh_dearmor_sshsig(sshsigbuf)
    sshsigdata = ssh_parse_sshsig(sshsigbuf)
    Core.trace("parsed sshsig wrapper: %r", sshsigdata)

    keyblob = sshsigdata["publickey"]
    sigblob = sshsigdata["signature"]

    keydata = ssh_parse_publickey(keyblob)
    sigdata = ssh_parse_signature(sigblob)

    if args.publickey:
        agentkey = SshAgentKey(None, keyblob)
        if args.publickey == agentkey.publickey_base64():
            Core.debug("enveloped publickey matches provided")
        elif args.publickey == agentkey.publickey_base64(with_type=True):
            Core.debug("enveloped publickey matches provided")
        else:
            Core.die("enveloped publickey does not match provided")
    if args.fingerprint:
        agentkey = SshAgentKey(None, keyblob)
        if args.fingerprint == agentkey.fprint_md5_hex():
            Core.debug("enveloped publickey MD5 fingerprint matches provided one")
        elif args.fingerprint == agentkey.fprint_sha256_base64():
            Core.debug("enveloped publickey SHA256 fingerprint matches provided one")
        else:
            Core.die("enveloped publickey fingerprint does not match provided")
    if args.namespace:
        if args.namespace.encode() != sshsigdata["namespace"]:
            Core.die("enveloped namespace does not match provided")

    Core.trace("parsed publickey blob: %r", keydata)
    Core.trace("parsed signature blob: %r", sigdata)

    # Format the inner packet that will be signed.

    hash_algo = sshsigdata["sig_algo"].decode()
    sshsigblob = ssh_format_sshsigdata(namespace,
                                       hash_algo,
                                       hash_data(hash_algo, data))

    Core.trace("formatted inner packet: %r", sshsigblob)
    Core.trace("=> %r", ssh_parse_sshsigdata(sshsigblob))

    sig_algo = "sha512"
    Core.trace("=> %s(inner): %r", sig_algo, hash_data(sig_algo, sshsigblob))

    print("verify:", cry_verify_signature(sshsigblob, keydata, sigdata))

else:
    buf = open("/tmp/pkt", "rb").read()
    sbuf = ssh_parse_sshsigdata(buf)
    pprint(sbuf)
