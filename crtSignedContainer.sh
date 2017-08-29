#!/bin/bash
# Script to create a signed container.  Intended for op-build integration.

# Defaults, initial values
P=${0##*/}
MODE=local
PASS_ON_ERR=N

HW_KEY_ARGS=""
SW_KEY_ARGS=""
HW_SIG_ARGS=""
SW_SIG_ARGS=""
VERIFY_ARGS=""
DEBUG_ARGS=""
ADDL_ARGS=""

VERBOSE=""
DEBUG=""
WRAP=""
RC=0

# Functions
usage () {
    echo ""
    echo "	Options:"
    echo "	-h, --help              display this message and exit"
    echo "	-v, --verbose           show verbose output"
    echo "	-d, --debug             show additional debug output"
    echo "	-w, --wrap              column to wrap long output in verbose mode"
    echo "	-a, --hwPrivKeyA        file containing HW key A private key in PEM format"
    echo "	-b, --hwPrivKeyB        file containing HW key B private key in PEM format"
    echo "	-c, --hwPrivKeyC        file containing HW key C private key in PEM format"
    echo "	-p, --swPrivKeyP        file containing SW key P private key in PEM format"
    echo "	-q, --swPrivKeyQ        file containing SW key Q private key in PEM format"
    echo "	-r, --swPrivKeyR        file containing SW key R private key in PEM format"
    echo "	-l, --protectedPayload  file containing the payload to be signed"
    echo "	-i, --out               file to write containerized payload"
    echo "	-o, --code-start-offset code start offset for software header in hex"
    echo "	-f, --flags             prefix header flags in hex"
    echo "	-m, --mode              signing mode: local, independent or production"
    echo "	-L, --label             name or identifier of the module being built (8 char max)"
    echo "	    --validate          validate the container after build"
    echo "	    --verify            verify the container after build, against the provided"
    echo "	                        value, or filename containing value, of the HW Keys hash"
    echo ""
    exit 1
}

die () {
    echo "$P: $@" 1>&2
    exit 1
}

is_private_key () {
    openssl ec -pubout -in $1 &>/dev/null
}

is_public_key () {
    openssl ec -pubin -pubout -in $1 &>/dev/null
}

is_raw_key () {
    test $(stat -c%s "$K") -eq 133 -a \
         $(dd if="$K" bs=1 count=1 2>/dev/null | xxd -p) == "04"
}

to_upper () {
    echo $1 | tr a-z A-Z
}

checkKey () {
    # The variable name
    KEY_NAME=$1
    # The filename holding the key
    K=${!KEY_NAME}
    KEYS=0
    PUBKEYS=0

    if [ -n "$K" ]; then
        if [ -f "$K" ]; then
            if is_private_key "$K"; then
                KEYS=1
            elif is_public_key "$K"; then
                KEYS=1
                PUBKEYS=1
            elif is_raw_key "$K"; then
                KEYS=1
                PUBKEYS=1
            else
                die "Key $KEY_NAME is neither a public nor private key"
            fi
        else
            die "Can't open file: $K for $KEY_NAME"
        fi
    fi

    # Increment key counts accordingly
    if [[ $KEY_NAME =~ HW_KEY* ]]; then
        HW_KEY_COUNT=$(expr $HW_KEY_COUNT + $KEYS)
        HW_KEY_PUBKEY_COUNT=$(expr $HW_KEY_PUBKEY_COUNT + $PUBKEYS)
    elif [[ $KEY_NAME =~ SW_KEY* ]]; then
        SW_KEY_COUNT=$(expr $SW_KEY_COUNT + $KEYS)
        SW_KEY_PUBKEY_COUNT=$(expr $SW_KEY_PUBKEY_COUNT + $PUBKEYS)
    fi
}

# Main

# Convert long options to short
for arg in "$@"; do
  shift
  case "$arg" in
    "--help")       set -- "$@" "-h" ;;
    "--verbose")    set -- "$@" "-v" ;;
    "--debug")      set -- "$@" "-d" ;;
    "--wrap")       set -- "$@" "-w" ;;
    "--hwPrivKeyA") set -- "$@" "-a" ;;
    "--hwPrivKeyB") set -- "$@" "-b" ;;
    "--hwPrivKeyC") set -- "$@" "-c" ;;
    "--swPrivKeyP") set -- "$@" "-p" ;;
    "--swPrivKeyQ") set -- "$@" "-q" ;;
    "--swPrivKeyR") set -- "$@" "-r" ;;
    "--flags")      set -- "$@" "-f" ;;
    "--code-start-offset") set -- "$@" "-o" ;;
    "--protectedPayload")  set -- "$@" "-l" ;;
    "--out")        set -- "$@" "-i" ;;
    "--mode")       set -- "$@" "-m" ;;
    "--label   ")   set -- "$@" "-L" ;;
    "--sign-project-FW-token")   set -- "$@" "-L" ;;
    "--validate")   set -- "$@" "-8" ;;
    "--verify")     set -- "$@" "-9" ;;
    *)              set -- "$@" "$arg"
  esac
done

# Process command-line arguments
while getopts ?dvw:a:b:c:p:q:r:f:o:l:i:m:L:89: opt
do
  case "$opt" in
    v) VERBOSE="TRUE";;
    d) DEBUG="TRUE";;
    w) WRAP="`echo $OPTARG`";;
    a) HW_KEY_A="`echo $OPTARG`";;
    b) HW_KEY_B="`echo $OPTARG`";;
    c) HW_KEY_C="`echo $OPTARG`";;
    p) SW_KEY_P="`echo $OPTARG`";;
    q) SW_KEY_Q="`echo $OPTARG`";;
    r) SW_KEY_R="`echo $OPTARG`";;
    f) HW_FLAGS="`echo $OPTARG | tr A-Z a-z`";;
    o) CS_OFFSET="`echo $OPTARG | tr A-Z a-z`";;
    l) PAYLOAD="`echo $OPTARG`";;
    i) OUTPUT="`echo $OPTARG`";;
    m) MODE="`echo $OPTARG`";;
    L) LABEL="`echo $OPTARG`";;
    8) VALIDATE="TRUE";;
    9) VERIFY="`echo $OPTARG`";;
    h|\?) usage;;
  esac
done

# Check arguments
test -z "$PAYLOAD" && die "Input payload required"
test -z "$OUTPUT" && die "Destination imagefile required"
test ! -f "$PAYLOAD" && die "Can't open payload file: $PAYLOAD"

# Check input keys
HW_KEY_COUNT=0
HW_KEY_PUBKEY_COUNT=0
SW_KEY_COUNT=0
SW_KEY_PUBKEY_COUNT=0

for KEY in HW_KEY_A HW_KEY_B HW_KEY_C; do
    checkKey $KEY
done

for KEY in SW_KEY_P SW_KEY_Q SW_KEY_R; do
    checkKey $KEY
done

# Set cache directory
set ${TMPDIR:=/tmp}
SCRATCH_DIR=$TMPDIR
moniker="SIGNTOOL"
KEEP_CACHE=true

test -z "$LABEL" && KEEP_CACHE=false && LABEL="IMAGE"

TOPDIR=$(ls -1dt $SCRATCH_DIR/${moniker}_* 2>/dev/null | head -1)

if [ -n "$TOPDIR" ]; then
    crtTime=$(date -d @$(basename $TOPDIR | cut -d_ -f2))
    echo "--> $P: Using existing cache dir: $TOPDIR, created: $crtTime"
else
    buildID="${moniker}_$(date +%s)"
    TOPDIR=$SCRATCH_DIR/$buildID
    echo "--> $P: Creating new cache dir: $TOPDIR"
    mkdir $TOPDIR
fi

T=$TOPDIR/$LABEL

if [ -d "$T" ]; then
    echo "--> $P: Using existing cache subdir: $T"
else
    echo "--> $P: Creating new cache subdir: $T"
    mkdir $T
fi

# Set arguments for (program) execution
test -n "$VERBOSE" && DEBUG_ARGS="$DEBUG_ARGS -v"
test -n "$DEBUG" && DEBUG_ARGS="$DEBUG_ARGS -d"
test -n "$WRAP" && DEBUG_ARGS="$DEBUG_ARGS -w $WRAP"
test -n "$HW_FLAGS" && ADDL_ARGS="$ADDL_ARGS --hw-flags $HW_FLAGS"
test -n "$CS_OFFSET" && ADDL_ARGS="$ADDL_ARGS --sw-cs-offset $CS_OFFSET"
test -n "$LABEL" && ADDL_ARGS="$ADDL_ARGS --label $LABEL"

# Determine if validate or verify has been requested
test -n "$BR2_CONFIG" && source $BR2_CONFIG &> /dev/null
test -n "$BR2_OPENPOWER_SECUREBOOT_PASS_ON_VALIDATION_ERROR" && PASS_ON_ERR=Y

if [ -z "$VALIDATE" -a -n "$BR2_OPENPOWER_SECUREBOOT_CONTAINER_VALIDATE" ]
then
    VALIDATE="$BR2_OPENPOWER_SECUREBOOT_CONTAINER_VALIDATE"
fi

if [ -z "$VERIFY" -a -n "$BR2_OPENPOWER_SECUREBOOT_CONTAINER_VERIFY" ]
then
    VERIFY="$BR2_OPENPOWER_SECUREBOOT_CONTAINER_VERIFY"
fi

test -n "$VALIDATE" && VERIFY_ARGS="$VERIFY_ARGS --validate"
test -n "$VERIFY" && VERIFY_ARGS="$VERIFY_ARGS --verify $VERIFY"

# Get the public keys
SF_EPWD=/path/to/epwd.txt
SF_SSHKEY=/path/to/id_rsa.sign
SF_USER=sf_user
SF_SERVER=server.mydomain.com

if [ "$MODE" == "local" ]
then
    # Set args from cmdline params
    test -n "$HW_KEY_A" && HW_KEY_ARGS="$HW_KEY_ARGS -a $HW_KEY_A"
    test -n "$HW_KEY_B" && HW_KEY_ARGS="$HW_KEY_ARGS -b $HW_KEY_B"
    test -n "$HW_KEY_C" && HW_KEY_ARGS="$HW_KEY_ARGS -c $HW_KEY_C"
    test -n "$SW_KEY_P" && SW_KEY_ARGS="$SW_KEY_ARGS -p $SW_KEY_P"
    test -n "$SW_KEY_Q" && SW_KEY_ARGS="$SW_KEY_ARGS -q $SW_KEY_Q"
    test -n "$SW_KEY_R" && SW_KEY_ARGS="$SW_KEY_ARGS -r $SW_KEY_R"

elif [ "$MODE" == "production" ]
then
    SF_PROJECT_BASE=sign_ecc_pwr_hw_key
    for KEY in a b c; do
        SF_PROJECT=${SF_PROJECT_BASE}_${KEY}
        KEYFILE=project.$SF_PROJECT.HW_key_$KEY.raw

        # If no keyfile in the current dir, try to find one.
        # If no keyfile found, try to get one.
        if [ -f "$T/$KEYFILE" ]
        then
            echo "--> $P: Found key for HW key $(to_upper $KEY)."
        else
            KEYFOUND=$(find $TOPDIR -name $KEYFILE | head -1)

            if [ -n "$KEYFOUND" ]
            then
                echo "--> $P: Found key for HW key $(to_upper $KEY)."
                cp -p $KEYFOUND $T/
            else
                echo "--> $P: Requesting public key for HW key $(to_upper $KEY)..."
                sf_client -stdout -project getpubkeyecc -param "-signproject $SF_PROJECT" \
                          -epwd $SF_EPWD -comments "Requesting $SF_PROJECT"  \
                          -url sftp://$SF_USER@$SF_SERVER -pkey $SF_SSHKEY -o $T/$KEYFILE
                # TODO Check return code, fail on error...
                echo "--> $P: Retrieved public key for HW key $(to_upper $KEY)."
            fi
        fi

        # Set args from project files
        HW_KEY_ARGS="$HW_KEY_ARGS -$KEY $T/$KEYFILE"
    done

    SF_PROJECT_BASE=sign_ecc_pwr_fw_key_op_bld
    for KEY in p; do
        SF_PROJECT=${SF_PROJECT_BASE}_${KEY}
        KEYFILE=project.$SF_PROJECT.SW_key_$KEY.raw

        if [ -f "$T/$KEYFILE" ]
        then
            echo "--> $P: Found key for SW key $(to_upper $KEY)."
        else
            KEYFOUND=$(find $TOPDIR -name $KEYFILE | head -1)

            if [ -n "$KEYFOUND" ]
            then
                echo "--> $P: Found key for SW key $(to_upper $KEY)."
                cp -p $KEYFOUND $T/
            else
                echo "--> $P: Requesting public key for SW key $(to_upper $KEY)..."
                sf_client -stdout -project getpubkeyecc -param "-signproject $SF_PROJECT" \
                          -epwd $SF_EPWD -comments "Requesting $SF_PROJECT" \
                          -url sftp://$SF_USER@$SF_SERVER -pkey $SF_SSHKEY -o $T/$KEYFILE
                # TODO Check return code, fail on error...
                echo "--> $P: Retrieved public key for SW key $(to_upper $KEY)."
            fi
        fi

        SW_KEY_ARGS="$SW_KEY_ARGS -$KEY $T/$KEYFILE"
    done

elif [ -n "$MODE" ]
then
    die "Unsupported mode: $MODE"
fi

# Build enough of the container to create the Prefix and Software headers
echo "--> $P: Generating signing requests..."
create-container $HW_KEY_ARGS $SW_KEY_ARGS \
                 --payload $PAYLOAD --imagefile $OUTPUT \
                 --dumpPrefixHdr $T/prefix_hdr --dumpSwHdr $T/software_hdr \
                 $DEBUG_ARGS \
                 $ADDL_ARGS

# Prepare the HW and SW key signatures
FOUND=""

if [ "$MODE" == "local" ]
then
    for KEY in a b c; do
        SIGFILE=HW_key_$KEY.sig
        name=HW_KEY_$(to_upper $KEY); eval KEYFILE=\$$name;

        # If no signature found, try to generate one.
        if [ -f "$T/$SIGFILE" ]
        then
            echo "--> $P: Found signature for HW key $(to_upper $KEY)."
        elif test -f $KEYFILE && is_private_key $KEYFILE
        then
            echo "--> $P: Generating signature for HW key $(to_upper $KEY)..."
            openssl dgst -SHA512 -sign $KEYFILE $T/prefix_hdr > $T/$SIGFILE
        else
            echo "--> $P: No signature found and no private key available for HW key $(to_upper $KEY), skipping."
            continue
        fi

        FOUND="${FOUND}$(to_upper $KEY),"
        HW_SIG_ARGS="$HW_SIG_ARGS -$(to_upper $KEY) $T/$SIGFILE"
    done

    for KEY in p q r; do
        SIGFILE=SW_key_$KEY.sig
        name=SW_KEY_$(to_upper $KEY); eval KEYFILE=\$$name;

        # If no signature found, try to generate one.
        if [ -f "$T/$SIGFILE" ]
        then
            echo "--> $P: Found signature for SW key $(to_upper $KEY)."
        elif test -f $KEYFILE && is_private_key $KEYFILE
        then
            echo "--> $P: Generating signature for SW key $(to_upper $KEY)..."
            openssl dgst -SHA512 -sign $KEYFILE $T/software_hdr > $T/$SIGFILE
        else
            echo "--> $P: No signature found and no private key available for SW key $(to_upper $KEY), skipping."
            continue
        fi

        FOUND="${FOUND}$(to_upper $KEY),"
        SW_SIG_ARGS="$SW_SIG_ARGS -$(to_upper $KEY) $T/$SIGFILE"
    done

elif [ "$MODE" == "production" ]
then
    SF_PROJECT_BASE=sign_ecc_pwr_hw_key
    for KEY in a b c; do
        SF_PROJECT=${SF_PROJECT_BASE}_${KEY}
        SIGFILE=project.$SF_PROJECT.HW_sig_$KEY.raw

        # If no signature in the current dir, try to find one.
        # If no signature found, request one.
        if [ -f "$T/$SIGFILE" ]
        then
            echo "--> $P: Found signature for HW key $(to_upper $KEY)."
        else
            SIGFOUND=$(find $TOPDIR -name $SIGFILE | head -1)

            if [ -n "$SIGFOUND" ]
            then
                echo "--> $P: Found signature for HW key $(to_upper $KEY)."
                cp -p $SIGFOUND $T/
            else
                echo "--> $P: Requesting signature for HW key $(to_upper $KEY)..."
                sf_client -stdout -project $SF_PROJECT -epwd $SF_EPWD \
                          -comments "Requesting sig for $SF_PROJECT" \
                          -url sftp://$SF_USER@$SF_SERVER -pkey $SF_SSHKEY \
                          -payload  $T/prefix_hdr -o $T/$SIGFILE
                # TODO Check return code, fail on error...
                echo "--> $P: Retrieved signature for HW key $(to_upper $KEY)."
            fi
        fi

        FOUND="${FOUND}$(to_upper $KEY),"
        HW_SIG_ARGS="$HW_SIG_ARGS -$(to_upper $KEY) $T/$SIGFILE"
    done

    SF_PROJECT_BASE=sign_ecc_pwr_fw_key_op_bld
    for KEY in p; do
        SF_PROJECT=${SF_PROJECT_BASE}_${KEY}
        SIGFILE=project.$SF_PROJECT.SW_sig_$KEY.raw

        # If no signature in the current dir, request one.
        if [ -f "$T/$SIGFILE" ]
        then
            echo "--> $P: Found signature for SW key $(to_upper $KEY)."
        else
            echo "--> $P: Requesting signature for SW key $(to_upper $KEY)..."
            sha512sum $T/software_hdr | cut -d' ' -f1 | xxd -p -r > $T/software_hdr.sha512.bin
            sf_client -stdout -project $SF_PROJECT -epwd $SF_EPWD \
                      -comments "Requesting sig for $LABEL from $SF_PROJECT" \
                      -url sftp://$SF_USER@$SF_SERVER -pkey $SF_SSHKEY \
                      -payload $T/software_hdr.sha512.bin -o $T/$SIGFILE
            # TODO Check return code, fail on error...
            echo "--> $P: Retrieved signature for SW key $(to_upper $KEY)."
        fi

        FOUND="${FOUND}$(to_upper $KEY),"
        SW_SIG_ARGS="$SW_SIG_ARGS -$(to_upper $KEY) $T/$SIGFILE"
    done
fi

# Build the full container
if [ -n "$HW_SIG_ARGS" -o -n "$SW_SIG_ARGS" ]; then
    echo "--> $P: Have signatures for keys $FOUND adding to container..."
    create-container $HW_KEY_ARGS $SW_KEY_ARGS \
                     $HW_SIG_ARGS $SW_SIG_ARGS \
                     --payload $PAYLOAD --imagefile $OUTPUT \
                     $DEBUG_ARGS \
                     $ADDL_ARGS
else
    echo "--> $P: No signatures available."
fi

echo "--> $P: Container $LABEL build completed."

# Validate, verify the container
if [ -n "$VALIDATE" -o -n "$VERIFY" ]; then
    echo
    print-container --imagefile $OUTPUT --no-print $VERIFY_ARGS $DEBUG_ARGS
    test $? -ne 0 && test $PASS_ON_ERR == N && RC=1
fi

# Cleanup
if [ $KEEP_CACHE == false ]; then
    echo "--> $P: Removing cache subdir: $T"
    rm -rf $T
    T=$(dirname $T)

    if rmdir $T; then
        echo "--> $P: Removing cache dir: $T"
    else
        echo "--> $P: Not removing cache dir: $T"
    fi
fi

exit $RC
