#!/bin/bash
# Script to create a signed container.  Intended for op-build integration.

VERBOSE=""
DEBUG=""
WRAP=""
RC=0

P=${0##*/}

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

checkKey () {
    # The variable name
    KEY_NAME=$1
    # The filename holding the key
    K=${!KEY_NAME}
    KEYS=0
    PUBKEYS=0

    if [ -n "$K" ]; then
        if [ -f $K ]; then
            if is_private_key $K; then
                KEYS=1
            elif is_public_key $K; then
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
    "--label   ")   set -- "$@" "-L" ;;
    "--sign-project-FW-token")   set -- "$@" "-L" ;;
    "--validate")   set -- "$@" "-8" ;;
    "--verify")     set -- "$@" "-9" ;;
    *)              set -- "$@" "$arg"
  esac
done

# Process command-line arguments
while getopts ?dvw:a:b:c:p:q:r:f:o:l:i:L:89: opt
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
HW_KEY_ARGS=""
SW_KEY_ARGS=""
HW_SIG_ARGS=""
SW_SIG_ARGS=""
VERIFY_ARGS=""
DEBUG_ARGS=""
ADDL_ARGS=""

[ -n "$HW_KEY_A" ] && HW_KEY_ARGS="$HW_KEY_ARGS -a $HW_KEY_A"
[ -n "$HW_KEY_B" ] && HW_KEY_ARGS="$HW_KEY_ARGS -b $HW_KEY_B"
[ -n "$HW_KEY_C" ] && HW_KEY_ARGS="$HW_KEY_ARGS -c $HW_KEY_C"
[ -n "$SW_KEY_P" ] && SW_KEY_ARGS="$SW_KEY_ARGS -p $SW_KEY_P"
[ -n "$SW_KEY_Q" ] && SW_KEY_ARGS="$SW_KEY_ARGS -q $SW_KEY_Q"
[ -n "$SW_KEY_R" ] && SW_KEY_ARGS="$SW_KEY_ARGS -r $SW_KEY_R"

[ -n "$VERBOSE" ] && DEBUG_ARGS="$DEBUG_ARGS -v"
[ -n "$DEBUG" ] && DEBUG_ARGS="$DEBUG_ARGS -d"
[ -n "$WRAP" ] && DEBUG_ARGS="$DEBUG_ARGS -w $WRAP"
[ -n "$HW_FLAGS" ] && ADDL_ARGS="$ADDL_ARGS --hw-flags $HW_FLAGS"
[ -n "$CS_OFFSET" ] && ADDL_ARGS="$ADDL_ARGS --sw-cs-offset $CS_OFFSET"

[ -n "$VALIDATE" ] && VERIFY_ARGS="$VERIFY_ARGS --validate"
[ -n "$VERIFY" ] && VERIFY_ARGS="$VERIFY_ARGS --verify $VERIFY"
[ -n "$LABEL" ] && ADDL_ARGS="$ADDL_ARGS --label $LABEL"

# Build enough of the container to create the Prefix and Software headers
echo "--> $P: Generating signing requests..."
create-container $HW_KEY_ARGS $SW_KEY_ARGS \
                 --payload $PAYLOAD --imagefile $OUTPUT \
                 --dumpPrefixHdr $T/prefix_hdr --dumpSwHdr $T/software_hdr \
                 $DEBUG_ARGS \
                 $ADDL_ARGS

# Sign the Prefix header (all 3 HW keys are required)
if [ "$HW_KEY_COUNT" -eq "3" -a "$HW_KEY_PUBKEY_COUNT" -eq "0" ]
then
    echo "--> $P: Executing signing request for HW keys A,B,C..."
    openssl dgst -SHA512 -sign $HW_KEY_A $T/prefix_hdr > $T/hw_key_a.sig
    openssl dgst -SHA512 -sign $HW_KEY_B $T/prefix_hdr > $T/hw_key_b.sig
    openssl dgst -SHA512 -sign $HW_KEY_C $T/prefix_hdr > $T/hw_key_c.sig
fi

# Sign the Software header (at least one SW key is required)
if [ "$SW_KEY_COUNT" -gt "0" -a "$SW_KEY_PUBKEY_COUNT" -eq "0" ]
then
    if [ -n "$SW_KEY_P" ]; then
        echo "--> $P: Executing signing request for SW key P..."
        openssl dgst -SHA512 -sign $SW_KEY_P $T/software_hdr > $T/sw_key_p.sig
    fi

    if [ -n "$SW_KEY_Q" ]; then
        echo "--> $P: Executing signing request for SW key Q..."
        openssl dgst -SHA512 -sign $SW_KEY_Q $T/software_hdr > $T/sw_key_q.sig
    fi

    if [ -n "$SW_KEY_R" ]; then
        echo "--> $P: Executing signing request for SW key R..."
        openssl dgst -SHA512 -sign $SW_KEY_R $T/software_hdr > $T/sw_key_r.sig
    fi
fi

# Find signatures
FOUND=""
if [ -f $T/hw_key_a.sig ]; then
    FOUND="${FOUND}A,"
    HW_SIG_ARGS="$HW_SIG_ARGS -A $T/hw_key_a.sig"
fi

if [ -f $T/hw_key_b.sig ]; then
    FOUND="${FOUND}B,"
    HW_SIG_ARGS="$HW_SIG_ARGS -B $T/hw_key_b.sig"
fi

if [ -f $T/hw_key_c.sig ]; then
    FOUND="${FOUND}C,"
    HW_SIG_ARGS="$HW_SIG_ARGS -C $T/hw_key_c.sig"
fi

if [ -f $T/sw_key_p.sig ]; then
    FOUND="${FOUND}P,"
    SW_SIG_ARGS="$SW_SIG_ARGS -P $T/sw_key_p.sig"
fi

if [ -f $T/sw_key_q.sig ]; then
    FOUND="${FOUND}Q,"
    SW_SIG_ARGS="$SW_SIG_ARGS -Q $T/sw_key_q.sig"
fi

if [ -f $T/sw_key_r.sig ]; then
    FOUND="${FOUND}R,"
    SW_SIG_ARGS="$SW_SIG_ARGS -R $T/sw_key_r.sig"
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

echo "--> $P: Container build completed."

# Validate, verify the container.
if [ -n "$VALIDATE" -o -n "$VERIFY" ]; then
    echo
    print-container --imagefile $OUTPUT --no-print $VERIFY_ARGS $DEBUG_ARGS
    RC=$?
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
