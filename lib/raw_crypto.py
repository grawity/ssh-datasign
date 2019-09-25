from .constants import sigalgo_to_keyalgo
from .exceptions import UnsupportedKeyType, UnsupportedSignatureType

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
        import hashlib
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
