#!/usr/bin/env python3
import argparse
import binascii
import enum
import hashlib
import os
import socket
import sshpkt
from pprint import pprint

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
        dgst = "MD5:" + ":".join(["%02x" % x for x in dgst])
        return dgst

    def fprint_sha256_base64(self):
        dgst = hashlib.sha256(self.keyblob).digest()
        dgst = "SHA256:" + binascii.b2a_base64(dgst, newline=False).decode()
        return dgst

    def sign_data(self, *args, **kwargs):
        return self.agent.sign_data(*args, keyblob=self.keyblob, **kwargs)

class SshAgentConnection(object):
    def __init__(self, path=None):
        if not path:
            path = os.environ["SSH_AUTH_SOCK"]
        self.path = path
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.path)
        self.stream = sshpkt.SshStream(self.sock)

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
        (sigalgo, sigvalue) = pkt.read_message("bb")
        return sigvalue

data = b"foo"
fpr = "SHA256:38BnD7+DlQfbHQIWSoFKgkD0MT6CW0OXWiT8iS3rG0g="

agent = SshAgentConnection()
key = agent.get_key_by_fprint(fpr)
sig = key.sign_data(data)

print(binascii.b2a_base64(sig).decode())
