import binascii
import io
from lib.binary_io import SshReader, SshWriter
from lib.packet_io import Packet
from lib.util import b64_encode, chunk

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

class SshsigWrapper(Packet):
    """The inner 'to-be-signed' data."""

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

class SshsigSignature(Packet):
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

    @classmethod
    def from_armored(klass, buf):
        return klass.from_bytes(ssh_dearmor_sshsig(buf))

    def to_armored(self):
        return ssh_enarmor_sshsig(self.to_bytes())
