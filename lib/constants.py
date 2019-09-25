sigalgo_to_keyalgo = {
    "rsa-sha2-256":     "ssh-rsa",
    "rsa-sha2-512":     "ssh-rsa",
}

sigalgo_to_digest = {
    "ssh-rsa":              "sha1",
    "rsa-sha2-256":         "sha256",
    "rsa-sha2-512":         "sha512",
    "ecdsa-sha2-nistp256":  "sha256",
    "ecdsa-sha2-nistp384":  "sha384",
    "ecdsa-sha2-nistp521":  "sha512",
    "ssh-ed25519":          "sha512",
    "ssh-ed448":            "sha512",
}
