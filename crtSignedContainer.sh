#!/bin/bash
#
# Script to create a signed container.  Intended for op-build integration.
#

# Defaults, initial values
P=${0##*/}

SIGN_MODE=local

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

#
# Functions
#
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
    echo "	-s, --scratchDir        scratch directory to use for file caching, etc."
    echo "	-L, --label             name or identifier of the module being built (8 char max)"
    echo "	    --validate          validate the container after build"
    echo "	    --verify            verify the container after build, against the provided"
    echo "	                        value, or filename containing value, of the HW Keys hash"
    echo "	    --sign-project-config   INI file containing configuration properties (options"
    echo "	                            set here override those set via cmdline or environment)"
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

to_lower () {
    echo $1 | tr A-Z a-z
}

to_upper () {
    echo $1 | tr a-z A-Z
}

checkKey () {
    # The variable name
    KEY_NAME=$1
    # The filename holding the key
    local K=${!KEY_NAME}
    local KEYS=0
    local PUBKEYS=0

    if [ -n "$K" ]; then
        # Handle the special values __skip, __get and _getkey
        if [ "$K" == __skip ]; then
            KEYS=0
        elif [ "$K" == __get -o "$K" == __getkey ]; then
            KEYS=1
            PUBKEYS=1

        # If it's a file, determine what kind of key it contains
        elif [ -f "$K" ]; then
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

parseIni () {
    local IFS=" ="
    local section property value

    while read property value
    do
        if echo "$property" | egrep -q "^;"
        then
            # This is a comment, skip it
            continue
        elif echo "$property" | egrep -q "\[.*]"
        then
            # This is a section header, read it
            section=$(echo $property | tr -d [] )
        elif test -n "$value"
        then
            # This is a property, set it
            declare -g "${section}_${property}=$value"
        fi
    done < $1
}

#
# Main
#

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
    "--scratchDir") set -- "$@" "-s" ;;
    "--label")      set -- "$@" "-L" ;;
    "--sign-project-FW-token")   set -- "$@" "-L" ;;
    "--sign-project-config")   set -- "$@" "-7" ;;
    "--validate")   set -- "$@" "-8" ;;
    "--verify")     set -- "$@" "-9" ;;
    *)              set -- "$@" "$arg"
  esac
done

# Process command-line arguments
while getopts ?dvw:a:b:c:p:q:r:f:o:l:i:m:s:L:7:89: opt
do
  case "$opt" in
    v) VERBOSE="TRUE";;
    d) DEBUG="TRUE";;
    w) WRAP="$OPTARG";;
    a) HW_KEY_A="$OPTARG";;
    b) HW_KEY_B="$OPTARG";;
    c) HW_KEY_C="$OPTARG";;
    p) SW_KEY_P="$OPTARG";;
    q) SW_KEY_Q="$OPTARG";;
    r) SW_KEY_R="$OPTARG";;
    f) HW_FLAGS="$OPTARG";;
    o) CS_OFFSET="$OPTARG";;
    l) PAYLOAD="$OPTARG";;
    i) OUTPUT="$OPTARG";;
    m) SIGN_MODE="$(to_lower $OPTARG)";;
    s) SB_SCRATCH_DIR="$OPTARG";;
    L) LABEL="$OPTARG";;
    7) PROJECT_INI="$OPTARG";;
    8) SB_VALIDATE="TRUE";;
    9) SB_VERIFY="$OPTARG";;
    h|\?) usage;;
  esac
done

# Process config properties from op-build _defconfig
test -n "$BR2_CONFIG" && source $BR2_CONFIG &> /dev/null
test -n "$BR2_OPENPOWER_SECUREBOOT_PASS_ON_VALIDATION_ERROR" && SB_PASS_ON_ERROR=Y

# Determine if validate or verify has been requested via the _defconfig
if [ -z "$SB_VALIDATE" -a -n "$BR2_OPENPOWER_SECUREBOOT_CONTAINER_VALIDATE" ]
then
    SB_VALIDATE="$BR2_OPENPOWER_SECUREBOOT_CONTAINER_VALIDATE"
fi

if [ -z "$SB_VERIFY" -a -n "$BR2_OPENPOWER_SECUREBOOT_CONTAINER_VERIFY" ]
then
    SB_VERIFY="$BR2_OPENPOWER_SECUREBOOT_CONTAINER_VERIFY"
fi

# These are the only env vars that override a command line option
test -n "$SB_SIGN_MODE" && SIGN_MODE="$(to_lower $SB_SIGN_MODE)"
test -n "$SB_PROJECT_INI" && PROJECT_INI="$SB_PROJECT_INI"

# What op-buid calls development mode, we call local mode
test "$SIGN_MODE" == development && SIGN_MODE=local

#
# Parse INI file
#
if [ -n "$PROJECT_INI" ]
then
    test ! -f "$PROJECT_INI" && die "Can't open INI file: $PROJECT_INI"

    echo "--> $P: Parsing INI file: $PROJECT_INI"
    parseIni $PROJECT_INI

    SF_USER="$signer_userid"
    SF_SSHKEY="$signer_sshkey_file"
    SF_EPWD="$signer_epwd_file"
    SF_SERVER="$server_hostname"

    SB_VALIDATE="$signtool_validate"
    SB_VERIFY="$signtool_verify"
    SB_PASS_ON_ERROR="$signtool_pass_on_validation_error"
fi

#
# Check required arguments
#
test -z "$PAYLOAD" && die "Input payload required"
test -z "$OUTPUT" && die "Destination imagefile required"
test ! -f "$PAYLOAD" && die "Can't open payload file: $PAYLOAD"

if [ "$SIGN_MODE" == "production" ]
then
    test -z "$SF_USER" && die "Production mode selected but no signer userid provided"
    test -z "$SF_SSHKEY" && die "Production mode selected but no signer ssh key provided"
    test -z "$SF_EPWD" && die "Production mode selected but no signer ePWD provided"
    test -z "$SF_SERVER" && die "Production mode selected but no signframework server provided"
fi

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

#
# Set cache directory
#
: ${TMPDIR:=/tmp}
: ${SB_SCRATCH_DIR:=$TMPDIR}
: ${SB_KEEP_CACHE:=true}
: ${LABEL:=IMAGE}

moniker="SIGNTOOL"

test ! -d "$SB_SCRATCH_DIR" && die "Scratch directory not found: $SB_SCRATCH_DIR"

TOPDIR=$(ls -1dt $SB_SCRATCH_DIR/${moniker}_* 2>/dev/null | head -1)

if [ -n "$TOPDIR" ]; then
    crtTime=$(date -d @$(basename $TOPDIR | cut -d_ -f2))
    echo "--> $P: Using existing cache dir: $TOPDIR, created: $crtTime"
else
    buildID="${moniker}_$(date +%s)"
    TOPDIR=$SB_SCRATCH_DIR/$buildID
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

#
# Get the public keys
#
if [ "$SIGN_MODE" == "local" ]
then
    for KEY in a b c; do
        # This will evaluate the value of HW_KEY_A, HW_KEY_B, HW_KEY_C
        varname=HW_KEY_$(to_upper $KEY); KEYFILE=${!varname}

        # Handle the special values, or empty value
        test -z "$KEYFILE" && continue
        test "$KEYFILE" == __skip && continue
        test "$KEYFILE" == __get -o "$KEYFILE" == __getkey && \
            die "Cannot $KEYFILE $varname in $SIGN_MODE mode"

        # Add to HW_KEY_ARGS
        HW_KEY_ARGS="$HW_KEY_ARGS -$KEY $KEYFILE"
    done

    for KEY in p q r; do
        # Find the value of SW_KEY_P, SW_KEY_Q, SW_KEY_R
        varname=SW_KEY_$(to_upper $KEY); KEYFILE=${!varname}

        # Handle the special values, or empty value
        test -z "$KEYFILE" && break
        test "$KEYFILE" == __skip && break
        test "$KEYFILE" == __get -o "$KEYFILE" == __getkey && \
            die "Cannot $KEYFILE $varname in $SIGN_MODE mode"

        # Add to SW_KEY_ARGS
        SW_KEY_ARGS="$SW_KEY_ARGS -$KEY $KEYFILE"
    done

elif [ "$SIGN_MODE" == "production" ]
then
    SF_PROJECT_BASE=sign_ecc_pwr_hw_key
    for KEY in a b c; do
        varname=HW_KEY_$(to_upper $KEY); KEYFILE=${!varname}

        # Handle the special values, or empty value
        test -z "$KEYFILE" && continue
        test "$KEYFILE" == __skip && continue
        # TODO: Add full support for user-specified keys in Production mode.
        # Currently we use it only to check if __skip was specified.

        SF_PROJECT=${SF_PROJECT_BASE}_${KEY}
        KEYFILE=project.$SF_PROJECT.HW_key_$KEY.raw

        # If no keyfile in the current dir, try to find one. If none found, try to get one.
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
                sf_client -project getpubkeyecc -param "-signproject $SF_PROJECT" \
                          -epwd $SF_EPWD -comments "Requesting $SF_PROJECT"  \
                          -url sftp://$SF_USER@$SF_SERVER -pkey $SF_SSHKEY -o $T/$KEYFILE
                # TODO Check return code, fail on error...
                echo "--> $P: Retrieved public key for HW key $(to_upper $KEY)."
            fi
        fi

        # Add to HW_KEY_ARGS
        HW_KEY_ARGS="$HW_KEY_ARGS -$KEY $T/$KEYFILE"
    done

    SF_PROJECT_BASE=sign_ecc_pwr_fw_key_op_bld
    for KEY in p q r; do
        varname=SW_KEY_$(to_upper $KEY); KEYFILE=${!varname}

        # Handle the special values, or empty value
        test -z "$KEYFILE" && break
        test "$KEYFILE" == __skip && break

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
                sf_client -project getpubkeyecc -param "-signproject $SF_PROJECT" \
                          -epwd $SF_EPWD -comments "Requesting $SF_PROJECT" \
                          -url sftp://$SF_USER@$SF_SERVER -pkey $SF_SSHKEY -o $T/$KEYFILE
                # TODO Check return code, fail on error...
                echo "--> $P: Retrieved public key for SW key $(to_upper $KEY)."
            fi
        fi

        # Add to SW_KEY_ARGS
        SW_KEY_ARGS="$SW_KEY_ARGS -$KEY $T/$KEYFILE"
    done

elif [ -n "$SIGN_MODE" ]
then
    die "Unsupported mode: $SIGN_MODE"
fi

#
# Build enough of the container to create the Prefix and Software headers
#
echo "--> $P: Generating signing requests..."
create-container $HW_KEY_ARGS $SW_KEY_ARGS \
                 --payload $PAYLOAD --imagefile $OUTPUT \
                 --dumpPrefixHdr $T/prefix_hdr --dumpSwHdr $T/software_hdr \
                 $DEBUG_ARGS \
                 $ADDL_ARGS

#
# Prepare the HW and SW key signatures
#
FOUND=""

if [ "$SIGN_MODE" == "local" ]
then
    for KEY in a b c; do
        SIGFILE=HW_key_$KEY.sig
        varname=HW_KEY_$(to_upper $KEY); KEYFILE=${!varname}

        # Handle the special values, or empty value
        test -z "$KEYFILE" && continue
        test "$KEYFILE" == __skip && continue
        test "$KEYFILE" == __get -o "$KEYFILE" == __getkey && \
            die "Cannot $KEYFILE $varname in $SIGN_MODE mode"

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
        varname=SW_KEY_$(to_upper $KEY); KEYFILE=${!varname}

        # Handle the special values, or empty value
        test -z "$KEYFILE" && break
        test "$KEYFILE" == __skip && break
        test "$KEYFILE" == __get -o "$KEYFILE" == __getkey && \
            die "Cannot $KEYFILE $varname in $SIGN_MODE mode"

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

elif [ "$SIGN_MODE" == "production" ]
then
    SF_PROJECT_BASE=sign_ecc_pwr_hw_key
    for KEY in a b c; do
        SF_PROJECT=${SF_PROJECT_BASE}_${KEY}
        SIGFILE=project.$SF_PROJECT.HW_sig_$KEY.raw

        varname=HW_KEY_$(to_upper $KEY); KEYFILE=${!varname}

        # Handle the special values, or empty value
        test -z "$KEYFILE" && continue
        test "$KEYFILE" == __skip && continue
        test "$KEYFILE" == __getkey && continue
        # TODO: Add full support for user-specified keys in Production mode.
        # Currently we use it only to check if __skip or __getkey was specified.

        # If no signature in the current dir, try to find one. If none found, request one.
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
                sf_client -project $SF_PROJECT -epwd $SF_EPWD \
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
    for KEY in p q r; do
        SF_PROJECT=${SF_PROJECT_BASE}_${KEY}
        SIGFILE=project.$SF_PROJECT.SW_sig_$KEY.raw

        varname=SW_KEY_$(to_upper $KEY); KEYFILE=${!varname}

        # Handle the special values, or empty value
        test -z "$KEYFILE" && break
        test "$KEYFILE" == __skip && break
        test "$KEYFILE" == __getkey && continue

        # If no signature in the current dir, request one.
        if [ -f "$T/$SIGFILE" ]
        then
            echo "--> $P: Found signature for SW key $(to_upper $KEY)."
        else
            echo "--> $P: Requesting signature for SW key $(to_upper $KEY)..."
            sha512sum $T/software_hdr | cut -d' ' -f1 | xxd -p -r > $T/software_hdr.sha512.bin
            sf_client -project $SF_PROJECT -epwd $SF_EPWD \
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

#
# Build the full container
#
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

#
# Validate, verify the container
#
if [ "$(to_upper $SB_VALIDATE)" != Y -a \
     "$(to_upper $SB_VALIDATE)" != TRUE ]
then
    SB_VALIDATE=""
fi

if [ "$(to_upper $SB_PASS_ON_ERROR)" != Y -a \
     "$(to_upper $SB_PASS_ON_ERROR)" != TRUE ]
then
    SB_PASS_ON_ERROR=""
fi

test -n "$SB_VALIDATE" && VERIFY_ARGS="$VERIFY_ARGS --validate"
test -n "$SB_VERIFY" && VERIFY_ARGS="$VERIFY_ARGS --verify $SB_VERIFY"

if [ -n "$VERIFY_ARGS" ]; then
    echo
    print-container --imagefile $OUTPUT --no-print $VERIFY_ARGS $DEBUG_ARGS
    test $? -ne 0 && test -z $SB_PASS_ON_ERROR && RC=1
fi

#
# Cleanup
#
if [ $SB_KEEP_CACHE == false ]; then
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
