import io
import struct

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
