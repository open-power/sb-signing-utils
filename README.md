sb-signing-utils
================

A simple utility for signing firmware components for OpenPOWER Secure and Trusted Boot.

How Firmware Signing works on OpenPOWER
---------------------------------------

The core root of trust is in the CPU module (package). From the factory,
they come with "imprint" keys. The private key part is well known (i.e.
**the private key is published on the internet**), and
vendors, when putting modules into machines, will replace the imprint
key with their own key.

A hash of this key is stored in a SEEPROM inside the module (as there is
not enough space to store the full key). The full key is stored in the
Secure/Trusted Boot Header of the first bit of firmware loaded from flash
(PNOR).

All firmware loaded must be signed by this hardware key (in fact, there are
three hardware keys, BECAUSE REASONS)

In addition to the hardware key, there is also a software key (in fact, three
software keys, BECAUSE REASONS). This allows firmware to be developed
by a separate group to hardware (or multiple firmware loads for the same
hardware to be developed by separate entities). However, this necessitates
a two-step signing process (and an additional step to produce the final
container)

By default, op-build will produce a signed firmware image but with the
published imprint keys. As such you **MUST NOT** use these to implement
secure boot. **The default product from op-build is only suitable for development use.**

HOWTO
-----

This HOWTO signs a single payload (i.e. the contents of a partition). You
will need to repeat steps 1-3 for each signed bit of firmware. This may
be several FFS partitions in a PNOR image, or several files (depending
on platform).


Step 1: Software signing
------------------------

First, those doing the signing should **verify** the legitimacy of what
they are about to sign.

With each of the three software keys, the payload is signed. You do this
**on a secure system** like so:

```
  openssl dgst -sha512 -sign sw-key1-private.pem PAYLOAD > PAYLOAD.sw-key1-signature
```

(for each key, so if each private key is held by a separate entity, they must
do the same)

You then transfer the signatures (and **public** halves of the software keys)
to a machine with create-container and do the following:

```
  ./create-software-container \
      --software-signature1 PAYLOAD.sw-key1-signature \
      --software-signature2 PAYLOAD.sw-key2-signature \
      --software-signature3 PAYLOAD.sw-key3-signature \
      PAYLOAD PAYLOAD.software-container
```

The `PAYLOAD.software-container` now contains just the part of the header
that needs to be signed with the hardware keys.

Step 2: Signing with hardware keys
----------------------------------

Those doing the signing should **verify** the validity of what they're being
asked to sign.

For each of the hardware keys, sign the software-container. Do this
**on a secure system** with the hardware keys:

```
  openssl dgst -ecdsa-with-SHA512 -sign hw-key1-private.pem PAYLOAD.software-container > PAYLOAD.software-container-sig1
```

Now, the final step is creating the final container

Step 3: Assembling the final container
--------------------------------------

The `create-container` utility is executed as below, note that we do not
need to pass in the PAYLOAD.software-container that create-software-container
created as it can all be re-created from the keys and signatures we already
have.

```
  ./create-container --software-public-key1 sw-key1-public.pem \
                     --software-public-key2 sw-key2-public.pem \
                     --software-public-key3 sw-key3-public.pem \
                     --software-signature1  PAYLOAD.sw-key1-signature \
                     --software-signature2  PAYLOAD.sw-key2-signature \
                     --software-signature3  PAYLOAD.sw-key3-signature \
                     --hardware-public-key1 hw-key1-public.pem \
                     --hardware-public-key2 hw-key2-public.pem \
                     --hardware-public-key3 hw-key3-public.pem \
                     --hardware-signature1  PAYLOAD.software-container-sig1 \
                     --hardware-signature2  PAYLOAD.software-container-sig2 \
                     --hardware-signature3  PAYLOAD.software-container-sig3 \
                     PAYLOAD PAYLOAD.stb
```

You now have a `PAYLOAD.stb` which is signed with all of the correct keys and
will be able to be successfully verified during boot.
