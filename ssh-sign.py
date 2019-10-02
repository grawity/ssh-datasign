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
import sys

from lib.binary_io import *
from lib.constants import *
from lib.exceptions import *
from lib.raw_crypto import cry_verify_signature
from lib.ssh_agent import *

def b64_encode(buf):
    return binascii.b2a_base64(buf, newline=False).decode()

def chunk(vec, size):
    for i in range(0, len(vec), size):
        yield vec[i:i+size]


# Signature formats:
# https://tools.ietf.org/html/rfc4253#section-6.6
# https://tools.ietf.org/html/draft-ietf-curdle-rsa-sha2-00
# https://tools.ietf.org/html/draft-irtf-cfrg-eddsa-05
# https://tools.ietf.org/html/draft-ietf-curdle-ssh-ed25519-00

class Package():
    pass

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

class SSHSigWrap(Package):
    def __init__(self, *, namespace=b"",
                          reserved=b"",
                          hash_algo=None,
                          hash=None):
        self.namespace = namespace
        self.reserved = reserved
        self.hash_algo = hash_algo
        self.hash = hash

    @classmethod
    def from_bytes(klass, buf):
        self = klass()
        pkt = SshReader.from_bytes(buf)
        magic = pkt.read(6)
        if magic != b"SSHSIG":
            raise ValueError("magic preamble not found")
        self.namespace = pkt.read_string()
        self.reserved = pkt.read_string()
        self.hash_algo = pkt.read_string()
        self.hash = pkt.read_string()
        return self

    def to_bytes(self):
        pkt = SshWriter(io.BytesIO())
        pkt.write(b"SSHSIG")
        pkt.write_string(self.namespace)
        pkt.write_string(self.reserved)
        pkt.write_string(self.hash_algo)
        pkt.write_string(self.hash)
        return pkt.output_fh.getvalue()

class SSHSig(Package):
    def __init__(self, *, version=0x01,
                          public_key=None,
                          namespace=b"",
                          reserved=b"",
                          hash_algo=None,
                          signature=None):
        self.version = version
        self.public_key = public_key
        self.namespace = namespace
        self.reserved = reserved
        self.hash_algo = hash_algo
        self.signature = signature

    @classmethod
    def from_bytes(klass, buf):
        self = klass()
        pkt = SshReader.from_bytes(buf)
        magic = pkt.read(6)
        if magic != b"SSHSIG":
            raise ValueError("magic preamble not found")
        self.version = pkt.read_uint32()
        if self.version == 0x01:
            self.public_key = pkt.read_string()
            self.namespace = pkt.read_string()
            self.reserved = pkt.read_string()
            self.hash_algo = pkt.read_string()
            self.signature = pkt.read_string()
        else:
            raise UnsupportedVersion(version)
        return self

    def to_bytes(self):
        pkt = SshWriter(io.BytesIO())
        pkt.write(b"SSHSIG")
        pkt.write_uint32(self.version)
        if self.version == 0x01:
            pkt.write_string(self.public_key)
            pkt.write_string(self.namespace)
            pkt.write_string(self.reserved)
            pkt.write_string(self.hash_algo)
            pkt.write_string(self.signature)
        else:
            raise UnsupportedVersion(version)
        return pkt.output_fh.getvalue()

    def to_armored(self):
        return ssh_enarmor_sshsig(self.to_bytes())

def ssh_parse_sshsigdata(buf):
    obj = SSHSigWrap.from_bytes(buf)
    return obj.__dict__

def ssh_format_sshsigdata(namespace, hash_algo, hash):
    obj = SSHSigWrap(namespace=namespace,
                     reserved=b"",
                     hash_algo=hash_algo.encode(),
                     hash=hash)
    return obj.to_bytes()

def ssh_parse_sshsig(buf):
    obj = SSHSig.from_bytes(buf)
    return obj.__dict__

def ssh_format_sshsig(pubkey, namespace, hash_algo, signature):
    obj = SSHSig(public_key=pubkey,
                 namespace=namespace,
                 reserved=b"",
                 hash_algo=hash_algo.encode(),
                 signature=signature)
    return obj.to_bytes()

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

def hash_data(hash_algo, data):
    if hash_algo in {"sha1", "sha256", "sha512"}:
        return hashlib.new(hash_algo, data).digest()
    else:
        raise UnsupportedHashType(hash_algo)

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

    namespace = args.namespace or ""

    # Format the inner packet that will be signed.

    hash_algo = "sha512"
    data_wrapper = SSHSigWrap(namespace=namespace.encode(),
                              hash_algo=hash_algo.encode(),
                              hash=hash_data(hash_algo, data))
    data = data_wrapper.to_bytes()

    # Sign the packet.

    agent = SshAgentConnection()
    agentkey = agent.get_key_by_fprint(args.fingerprint)

    flags = 0
    if agentkey.keyalgo == "ssh-rsa":
    	flags |= SignRequestFlags.RSA_SHA2_256
    sigblob = agentkey.sign_data(data, flags)
    Core.trace("raw signature blob: %r", sigblob)

    # Show information.

    keydata = ssh_parse_publickey(agentkey.keyblob)
    sigdata = ssh_parse_signature(sigblob)
    Core.trace("parsed publickey blob: %r", keydata)
    Core.trace("parsed signature blob: %r", sigdata)

    hash_algo = sigalgo_to_digest[sigdata["algo"]]
    Core.info("Signed using %s" % sigdata)

    sshsig = SSHSig(public_key=agentkey.keyblob,
                    namespace=namespace.encode(),
                    hash_algo=hash_algo.encode(),
                    signature=sigblob)
    print(sshsig.to_armored().strip())

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

    keyblob = sshsigdata["public_key"]
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

    if True:
        # Format the inner packet that will be signed.
        hash_algo = sshsigdata["hash_algo"].decode()
        sshsigblob = ssh_format_sshsigdata(namespace,
                                           hash_algo,
                                           hash_data(hash_algo, data))

        Core.trace("formatted inner packet: %r", sshsigblob)
        Core.trace("=> %r", ssh_parse_sshsigdata(sshsigblob))
        data = sshsigblob

    print("verify:", cry_verify_signature(data, keydata, sigdata))

else:
    buf = open("/tmp/pkt", "rb").read()
    sbuf = ssh_parse_sshsigdata(buf)
    pprint(sbuf)
