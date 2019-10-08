import io

from lib.binary_io import *
from lib.exceptions import *

class Packet():
    @classmethod
    def from_bytes(klass, buf):
        self = klass()
        pkt = SshReader.from_bytes(buf)
        self._from_bytes(pkt)
        return self

    def to_bytes(self):
        pkt = SshWriter(io.BytesIO())
        self._to_bytes(pkt)
        return pkt.output_fh.getvalue()
