import struct
import io

class SshEndOfStream(Exception):
    pass

class SshStream(object):
    @classmethod
    def from_bytes(self, buf):
        return self(io.BytesIO(buf))

    def __init__(self, input_fd, output_fd=None):
        if not output_fd:
            output_fd = input_fd
        if hasattr(input_fd, "makefile"):
            input_fd = input_fd.makefile("rb")
        if hasattr(output_fd, "makefile"):
            output_fd = output_fd.makefile("wb")
        self.input_fd = input_fd
        self.output_fd = output_fd

    def read(self, *args):
        buf = self.input_fd.read(*args)
        if not buf:
            raise SshEndOfStream
        return buf

    def write(self, *args, flush=False):
        ret = self.output_fd.write(*args)
        if ret and flush:
            ret = self.output_fd.flush()
        return ret

    # trivial typed read/write

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
        return SshStream.from_bytes(buf)

    # struct read/write

    def read_struct(self, types):
        data = []
        for i, t in enumerate(types):
            if t == "B":
                data.append(self.read_byte())
            elif t == "L":
                data.append(self.read_uint32())
            elif t == "b":
                data.append(self.read_string())
            else:
                raise ValueError("unknown type %r" % (t))
        return data

    def read_message(self, types):
        pkt = self.read_string_pkt()
        return pkt.read_struct(types)

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
            else:
                raise ValueError("unknown type %r of %r" % (types[i], data[i]))
        if length_prefix:
            packed[0] = struct.calcsize(fmt) - 4
        buf = struct.pack(fmt, *packed)
        self.write(buf, flush=True)

    def write_message(self, types, *data):
        return self.write_struct(types, *data, length_prefix=True)
