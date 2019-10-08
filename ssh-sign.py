#!/usr/bin/env python3
# v0.1
# (c) 2018 Mantas Mikulėnas <grawity@gmail.com>
# Released under the MIT License (https://spdx.org/licenses/MIT)
import argparse
import enum
import hashlib
import io
from nullroute.core import Core
import os
from pprint import pprint
import sys

from lib.constants import *
from lib.exceptions import *
from lib.raw_crypto import cry_verify_signature
from lib.ssh_agent import *
from lib.ssh_public_key import *
from lib.sshsig import *
from lib.util import *

# Signature formats:
# https://tools.ietf.org/html/rfc4253#section-6.6
# https://tools.ietf.org/html/draft-ietf-curdle-rsa-sha2-00
# https://tools.ietf.org/html/draft-irtf-cfrg-eddsa-05
# https://tools.ietf.org/html/draft-ietf-curdle-ssh-ed25519-00

def hash_data(hash_algo, data):
    if hash_algo in {"sha1", "sha256", "sha512"}:
        return hashlib.new(hash_algo, data).digest()
    else:
        raise UnsupportedHashType(hash_algo)

rest = sys.argv[1:]

if rest:
    cmd, *rest = rest
else:
    Core.die("missing command (try 'sign' or 'verify')")

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
    data = SshsigWrapper(namespace=namespace.encode(),
                         hash_algo=hash_algo.encode(),
                         hash=hash_data(hash_algo, data)).to_bytes()

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
    Core.info("Signed using %s (%s)", hash_algo, sigdata["algo"])

    sshsig = SshsigSignature(public_key=agentkey.keyblob,
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

    namespace = args.namespace or ""

    sshsig_outer = SshsigSignature.from_armored(sshsigbuf)

    keyblob = sshsig_outer.public_key
    sigblob = sshsig_outer.signature

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
        if args.namespace.encode() != sshsig_outer.namespace:
            Core.die("enveloped namespace does not match provided")

    Core.trace("parsed publickey blob: %r", keydata)
    Core.trace("parsed signature blob: %r", sigdata)

    if True:
        # Format the inner packet that will be signed.
        hash_algo = sshsig_outer.hash_algo.decode()
        data = SshsigWrapper(namespace=namespace.encode(),
                             hash_algo=hash_algo.encode(),
                             hash=hash_data(hash_algo, data)).to_bytes()
        Core.trace("formatted inner packet: %r", data)
        Core.trace("=> %r", SshsigWrapper.from_bytes(data).__dict__)

    print("verify:", cry_verify_signature(data, keydata, sigdata))

else:
    Core.die("unknown command %r", cmd)
