#!/bin/bash -x

PAYLOAD=$1
OUTPUT=$2

if [ ! -f $PAYLOAD ]; then
	echo "Can't read PAYLOAD";
	exit 1;
fi

T=`mktemp -d`

# For imprint keys, we re-use HW imprint key A as the software key.
# We also use it 3 times, because this is a PoC and I'm lazy.

openssl dgst -SHA512 -sign hw_key_a.key $PAYLOAD > $T/sw_sig1

./create-software-container --software-signature1 $T/sw_sig1 \
	--software-signature2 $T/sw_sig1 \
	--software-signature3 $T/sw_sig1 \
	$PAYLOAD $T/software-container

openssl dgst -SHA512 -sign hw_key_a.key $T/software-container > $T/hw_sig1
openssl dgst -SHA512 -sign hw_key_b.key $T/software-container > $T/hw_sig2
openssl dgst -SHA512 -sign hw_key_c.key $T/software-container > $T/hw_sig3

./create-container --hardware-public-key1 hw_key_a.pub \
	--hardware-public-key2 hw_key_b.pub \
	--hardware-public-key3 hw_key_c.pub \
	--hardware-signature1 $T/hw_sig1 \
	--hardware-signature2 $T/hw_sig2 \
	--hardware-signature3 $T/hw_sig3 \
	--software-public-key1 hw_key_a.pub \
        --software-public-key2 hw_key_a.pub \
        --software-public-key3 hw_key_a.pub \
	--software-signature1 $T/sw_sig1 \
	--software-signature2 $T/sw_sig1 \
	--software-signature3 $T/sw_sig1 \
	$PAYLOAD $OUTPUT
