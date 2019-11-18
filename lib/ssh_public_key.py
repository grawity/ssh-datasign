from lib.binary_io import SshReader
from lib.exceptions import *

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
    elif algo == "sk-ecdsa-sha2-nistp256@openssh.com":
        # PROTOCOL.u2f
        data["curve"] = pkt.read_string()
        data["Q"] = pkt.read_string()
        data["appid"] = pkt.read_string()
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
    elif algo == "sk-ecdsa-sha2-nistp256@openssh.com":
        # PROTOCOL.u2f
        # TODO: The signature is made over a special packet, not raw data
        # TODO: Does this also use a subpacket?
        #sigpkt = pkt.read_string_pkt()
        data["r"] = pkt.read_mpint()
        data["s"] = pkt.read_mpint()
        data["flags"] = pkt.read_byte()
        data["counter"] = pkt.read_uint32()
    else:
        raise UnsupportedSignatureType(algo)
    return data

