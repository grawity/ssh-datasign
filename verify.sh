#!/bin/bash

# ssh-keygen -e -m PKCS8 -f ~/.ssh/id_global_2011-11-01.pub >

sign_pkeyutl() {
	local infile=$1 keyfile=$2 algo=sha1

	local dgstfile="$infile.sha1.tmp"
	local sigfile="$infile.sig"

	openssl dgst -$algo -binary "$infile" > "$dgstfile"

	openssl pkeyutl -sign \
		-in "$dgstfile" \
		-inkey "$keyfile" \
		-pkeyopt digest:$algo \
		-pkeyopt rsa_padding_mode:pkcs1 \
		-out "$sigfile" ;
}

sign_dgst() {
	local infile=$1 sigfile=$2 keyfile=$2 algo=sha1

	openssl dgst --$algo --sign "$keyfile" --sigopt rsa_padding_mode:pkcs1 "$infile" > "$sigfile"
}

verify_dgst() {
	local infile=$1 sigfile=$2 keyfile=$3 algo=sha1

	openssl dgst --$algo --verify "$keyfile" --signature "$sigfile" --sigopt rsa_padding_mode:pkcs1 "$infile"
}
