#!/usr/bin/perl
# IBM_PROLOG_BEGIN_TAG
# This is an automatically generated prolog.
#
# $Source: scripts/crtSignedContainer.pl $
#
# OpenPOWER sb-signing-utils Project
#
# Contributors Listed Below - COPYRIGHT 2016
# [+] International Business Machines Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.
#
# IBM_PROLOG_END_TAG
#
#
#############################################################
#
# This script supports development mode only at this point.
#
# It will allow the caller to either
# - create a valid FW key pair via openssl (in
#    development mode)
#
# OR
#  - create a signed container
#
#############################################################

use strict;
use Carp;
use Cwd;
use Pod::Usage;
use IO::File;
use POSIX qw(strftime);
use File::Temp qw/ tempfile tempdir /;
use Getopt::Long qw(GetOptions);
use Digest::SHA qw(sha512_hex);

############
#
# Constants
#
############
# Algorithm to use when calculating the digest value for the
# binary to be signed
#
use constant hexBytesPerHash      => 64;
use constant asciiCharPerHexByte  => 2;
use constant expectedHexPubKeyLen => 132;
use constant hexBytesPerSignature => 132;
use constant dec4k                => 4096;

############
#
# Variables
#
############

my $HASH_ALG  = "sha512sum";
my $HASH_FUNC = \&sha512_hex;


# This temporary directory is used to store the
# signatures that are generated,etc during this
# processing. It should be cleaned up at the end.
my $g_tmpdir = "";

my %g_var;
$g_var{signing_mode}      = "development"; # or 'production'

# only used when creating a key pair
$g_var{createAkeyPair}    = 0;
$g_var{createContainer}   = 1;   # create the container on each call
$g_var{verbose}           = 0;

my $g_pathPrefix          = "";
my $g_ldLibPathPrefix     = "";

# By default, the protected payload (and unprotected
# payload, if specified) is attached to the end of
# container object.
$g_var{attachPayloads} = 1;

# path to the sign tool/utility to call
# (used to validate that the Linux
# OS-supplied binary in /usr/bin is not
# at the top of the caller's $PATH)
$g_var{signutility} = `which signtool`;
chomp($g_var{signutility});


# The hardware keys are used to sign a digest of a
# structure containing the digest of the FW public keys.
# The signatures are stored in these binaries.
my ($g_hwsignA, $g_hwsignB, $g_hwsignC) = "";

my ($g_HWpubKeyA, $g_HWpubKeyB, $g_HWpubKeyC) = "";

# These are the FW public keys that are stored
# as a protected payload in the prefix key header.
my ($g_SWpubKeyP, $g_SWpubKeyQ, $g_SWpubKeyR) = "";

# Signatures that were generated associated with the FW
# public keys
my ($g_SWsignP, $g_SWsignQ, $g_SWsignR) = "";

my $g_cfgHelp = 0;
my $g_cfgMan  = 0;

# global temp vars
my $g_CMD      = "";
my $g_cmdParms = "";
my $g_rc       = 0;
my @g_cmdOut   = ();

####

GetOptions (
  'createKey:s'    => \$g_var{createKeyPair},
  'privKeyPath:s'  => \$g_var{newPrivKeyPath},
  'pubKeyPath:s'   => \$g_var{newPubKeyPath},


  'protectedPayload:s'   => \$g_var{protected_payload},
  'unprotectedPayload:s' => \$g_var{unprotected_payload},
  'out:s'                => \$g_var{signed_container_name},

  'hwPrivKeyA:s'         => \$g_var{HWprivKeyA},
  'hwPrivKeyB:s'         => \$g_var{HWprivKeyB},
  'hwPrivKeyC:s'         => \$g_var{HWprivKeyC},

  'swPrivKeyP:s'         => \$g_var{SWprivKeyP},
  'swPrivKeyQ:s'         => \$g_var{SWprivKeyQ},
  'swPrivKeyR:s'         => \$g_var{SWprivKeyR},

  'mode:s'               => \$g_var{signing_mode},

  'flags-fw-key-ind:s'  => \$g_var{flags_fw_key_ind},
  'code-start-offset:s' => \$g_var{code_start_offset},
  'cont-size:s'         => \$g_var{input_final_cont_size},
  'target-HRMOR:s'      => \$g_var{target_HRMOR},
  'inst-start:s'        => \$g_var{inst_start},

  'tempdir:s'           => \$g_var{inputTempDir},

  'update'              => sub { $g_var{createContainer} = 0},
  'noattach'            => sub { $g_var{attachPayloads} = 0},

  'help'                => \$g_cfgHelp,
  'man'                 => \$g_cfgMan,
  'verbose'             => \$g_var{verbose} ) || pod2usage(-verbose => 0);

pod2usage(-verbose => 1) if $g_cfgHelp;
pod2usage(-verbose => 2) if $g_cfgMan;

# for our intermediate files, put them in a space
# the caller defines
if ($g_var{inputTempDir}) {
    $g_tmpdir = $g_var{inputTempDir};
    if (!(-e "$g_tmpdir")) {
       system("mkdir -p $g_tmpdir");
       if ($?) {
          die "ERROR: could not create $g_tmpdir";
       }
    }
} else {
   # get a temp dir, mark it for clean up upon exit
   $g_tmpdir = tempdir(CLEANUP => 1);
}

############################################################


########################
#
#  (Optionally) load parameters from the input
#    parameter file.
#
#  Verify all the parameters.
#
########################

verifyParms();


#######################
#
#  Environment set up
#
#######################

# debug info - make sure we are running the right signing utility
print "signtool = $g_var{signutility}\n" if $g_var{verbose};
if ($g_var{signutility} =~ /^\/usr\/bin\/signtool/) {
    print "Current path = $ENV{PATH}\n";
    die "$g_var{signutility} is in your PATH. This signtool binary is not the correct one for this tool to call to perform the desired functions.\n";
}
# Hook to run the tool from in an alternate toolchain jail
$g_var{signutility} = "$ENV{ALT_HOST_TOOLCHAIN_JAIL} " . $g_var{signutility};

#######################
#
#    Mainline
#
#######################

# Called to create a private/public key pair using the
# ECDSA 512 algorithm
if ($g_var{createAkeyPair}) {

    if ($g_var{verbose}) {
      print "\n#############################################\n";
      print "### --------  Key Pair Creation  -------- ###\n";
    }
    if ($g_var{newPrivKeyPath}) {
    # caller requested a specific path to contain the new key pair
        my ($rc, $msg) = createKeyPair(
                       privKeyPath => $g_var{newPrivKeyPath},
                       pubKeyPath  => $g_var{newPubKeyPath},
                       verbose     => $g_var{verbose});
        if ($rc > 0) {
            die "$msg";
        } elsif ($g_var{verbose}) {
            print "New key pairs have been created as:\n $g_var{newPrivKeyPath} \n$g_var{newPubKeyPath}\n";
        }
        exit 0;
    }
}

# The public keys all are added to the signed container
# header(s), so do this one call to extract them from
# the private key files that the caller passed in
# (this step applicable to development mode only)
extractPubKeysFromPriv(
            mode   => $g_var{signing_mode},
            hwkeya => $g_var{HWprivKeyA},
            hwkeyb => $g_var{HWprivKeyB},
            hwkeyc => $g_var{HWprivKeyC},
            swkeyp => $g_var{SWprivKeyP},
            swkeyq => $g_var{SWprivKeyQ},
            swkeyr => $g_var{SWprivKeyR}
            );

# Concatenate the FW keys into one blob so their size
# and hash can be calculated
if ($g_var{verbose}) {
    print "\n##########################################################################\n";
    print "### --------  Concat FW keys, get size and hash of that blob  -------- ###\n";
}
my ($hdrPayloadSize, $hdrPayloadHash, $hdrHashLen) = prepFWkeyBlob();

if ($g_var{verbose}) {
    print "*************************** Calculated FW key info:\n";
    print "FW key hash size  : $hdrPayloadSize\n";
    print "FW key hash       : $hdrPayloadHash\n";
    print "FW key(s) hash len: $hdrHashLen\n";
}

#########
#
# Create an EC 521 Curve Keypair :
#   <sign utility> --mode development --create_key --privkeyfile ecpriv.pem --pubkeyfile ecpub.pem
#
# Sign a sha-512 digest using openssl keys created above
# echo "this is a test message" > /tmp/message.txt
# SHA512_SUM=`sha512sum /tmp/message.txt | awk '{print $1}'`
# <sign utility> --mode development --sign --projname ecpriv.pem --sigfile message.sig --digest $SHA512_SUM
#
# Verify a sha-512 digest signed by openssl keys
# echo "this is a test message" > /tmp/message.txt
# SHA512_SUM=`sha512sum /tmp/message.txt | awk '{print $1}'`
# <sign utility> --mode development --verify --pubkeyfile ecpub.pem --sigfile message.sig --digest $SHA512_SUM
#
##########

if ($g_var{createContainer}) {
    if ($g_var{verbose}) {
        print "\n###############################################\n";
        print "### ---- Create the basic container header ----- ####\n";

        print "\n\nCall the tool to create the prefix header structure for a signed container (which includes some defaults and signature placeholders)\n";
    }
    $g_cmdParms = "--create-container";
    updateContainer($g_cmdParms);

    if ($g_var{verbose}) {
        print "\nNewly-created (mostly-empty signed container, with just a few default values set in it) can be found in:\n";
        print "$g_var{signed_container_name}\n";
    }
} else {
    if ($g_var{verbose}) {
        print "Skip creation of the container.\n";
    }
}

if ($g_var{verbose}) {
    print "\n###########################################################\n";
    print "### ----  Start updating fields in the container ----- ####\n";

    print "\nNow updating some of the base fields in the container\n";
}

######################
#
# Fields at the top of the hardware header

if ($g_var{target_HRMOR}) {
  if ($g_var{verbose}) {
      print "Now update the target HRMOR in the container\n";
  }
  $g_cmdParms = "--fldname target-hrmor --fldvalue $g_var{target_HRMOR}";
  updateContainer($g_cmdParms);
}

if ($g_var{inst_start}) {
  if ($g_var{verbose}) {
      print "Now update the instruction start stack pointer address in the container\n";
  }
  $g_cmdParms = "--fldname stack-pointer --fldvalue $g_var{inst_start}";
  updateContainer($g_cmdParms);
}

#########################
#
# Make sure the hardware prefix header fields are filled in

if ($g_var{flags_fw_key_ind}) {
  if ($g_var{verbose}) {
      print "Now update the firmware key indicator flags in the container\n";
  }
  $g_cmdParms = "--fldname hdr-flags --fldvalue $g_var{flags_fw_key_ind} ";
  updateContainer($g_cmdParms);
}

if ($g_var{verbose}) {
    print "Now update the prefix key header's protected payload size in the container\n";
}
# header's protected payload size must be the hex represenation of:
#  # bytes * number of FW public keys
my $verifySize = expectedHexPubKeyLen * $g_var{in_swKeyCount};
my $hexSize = convertValueToHexStr($verifySize);
if ($hexSize != $hdrPayloadSize) {
    die "ERROR: Expected size for the 'header payload size'is $hexSize (decimal size, $verifySize). Actual size is $hdrPayloadSize. ";
}
$g_cmdParms = "--fldname hdr-payload-size --fldvalue $hdrPayloadSize";
updateContainer($g_cmdParms);

my $verifyHashLen   = length($hdrPayloadHash);
my $hashShouldBeLen = hexBytesPerHash * asciiCharPerHexByte;
if ($verifyHashLen != $hashShouldBeLen) {
    die "ERROR: The length of the header payload hash' should be $hashShouldBeLen. Actual value is $verifyHashLen";
}

print "\n*****  Update the 'hash of protected payload' value in the prefix key header\n" if $g_var{verbose};
$g_cmdParms = "--fldname hdr-payload-hash --fldvalue $hdrPayloadHash ";
updateContainer($g_cmdParms);

# Update the FW public keys into the container
#   (Need to do this here so the FW public key count is valid in the
#  hardware header before the payload is hashed and signed)
SWkeys();

###############
#
# call <sign utility> to compute a signature over the digest
# of the hardware prefix header (digest excludes HW signatures
# and FW public keys)
#
# Get the digest of the hardware prefix header (digest excludes
# HW signatures and FW public keys)
$g_CMD = "$g_var{signutility} --imagefile $g_var{signed_container_name} --calchash --fldtype prefix_hdr";
my $hwPrefixHdrDigest = `$g_CMD`;
if ($?) {
    die "ERROR: Failed to get the digest of the hardware prefix header.\n";
}
chomp($hwPrefixHdrDigest);
print "Hardware prefix header digest: $hwPrefixHdrDigest\n" if $g_var{verbose};

#
# Sign that digest using each of the hardware private keys to
# get the hdw signatures
signPrefixKeyHeaderDigest(digestToSign => $hwPrefixHdrDigest);

# Update the hardware keys and signatures into the
# container
HWkeyInfo();


###############
#
#   Software header
#

# Calculate the size of the binary that we are to sign and
# get the associated hash value.
if ($g_var{verbose}) {
  print "\n#################################################################\n";
  print "### ------  Calc size and hash of protected payload ------ ###\n";
}
my ($decSz, $sfwPayloadSize, $sfwPayloadHash, $sfwHashLen) = getSizeAndHash($g_var{protected_payload});

if ($g_var{verbose}) {
    print "Binary size : $sfwPayloadSize\n";
    print "Binary hash : $sfwPayloadHash\n";
    print "hash len    : $sfwHashLen\n";
}

# code start offset is specified as "x(hex value)"
if ($g_var{code_start_offset}) {
  # normalize values back to decimal (since the
  # caller can pass in '0xZZZ' or 'ZZZ') to allow
  # for an easier comparison
  my $dec_code_start = hex($g_var{code_start_offset});
  my $dec_payloadlen = hex($sfwPayloadSize);
  if ($dec_code_start >= $dec_payloadlen) {
     die "ERROR: code-start-offset, $g_var{code_start_offset}, appears to be outside the bounds of the protected payload, $g_var{protected_payload}; size of which (in hex) is $sfwPayloadSize\n";
  }
  if ($g_var{verbose}) {
      print "Now update the code start offset in the container\n";
  }
  $g_cmdParms = "--fldname sw-code-start-offset --fldvalue $g_var{code_start_offset}";
  updateContainer($g_cmdParms);
}

# Update the size of the software payload (the size of the
# binary the caller asked us to sign)
$g_cmdParms = "--fldname sw-payload-size --fldvalue $sfwPayloadSize";
updateContainer($g_cmdParms);

# Add the protected payload hash to the container
print  "\nAdd the protected payload hash to the container\n" if $g_var{verbose};
$g_cmdParms = "--fldname sw-payload-hash --fldvalue $sfwPayloadHash";
updateContainer($g_cmdParms);

###############
#
# call <sign utility> to get a signature over the digest
#  of the software header (excluding software signatures
#  and padding)
#

$g_CMD = "$g_var{signutility} --imagefile $g_var{signed_container_name} --calchash --fldtype software_hdr";
my $sfwHeaderDigest = `$g_CMD`;
if ($?) {
   die "ERROR: Failure encountered creating the software header digest";
}
chomp($sfwHeaderDigest);
print "Software header digest:  $sfwHeaderDigest\n" if $g_var{verbose};

# Sign the software header digest
signSoftwareHeaderDigest(hashToSign => $sfwHeaderDigest);


#########
#
# Finish up by updating the FW signatures, and
# (optionally) attaching the protected and
# unprotected payloads.

# Update the software signatures into the container
SWsigns();

# Attach the binary that we just created a signature for
# to make a temporary object so we can get what will be
# the size of the final container object.
my $tmpFinalContainer = "";
my $prc = 0;
my $decSz         = 0;
my $containerSize = 0;
my $containerHash = "";
my $contHashLen   = 0;
if ($g_var{attachPayloads}) {
    $tmpFinalContainer = $g_var{signed_container_name} . "_temp";
    attachBinaryToContainer(finalContainer => $g_var{signed_container_name},
                            protected      => $g_var{protected_payload},
                            unprotected    => $g_var{unprotected_payload},
                            outfile        => $tmpFinalContainer,
                            createFinal    => 0);

    print "\nCalculate the size of the interim final container\n" if $g_var{verbose};
    ($decSz, $containerSize, $containerHash, $contHashLen) = getSizeAndHash($tmpFinalContainer);
    if ($decSz <= dec4k) {
       # make sure final container will be > 4k
       # ie, the payload is actually greater
       # than 0 bytes long
       die "ERROR: container size for $tmpFinalContainer is less than or equal to 4k";
    }
} else {
    # get the size of the container (the header) alone
    ($decSz, $containerSize, $containerHash, $contHashLen) = getSizeAndHash($g_var{signed_container_name});
    if ($decSz != dec4k) {
       # make sure the header is 4k
       die "ERROR: $g_var{signed_container_name} is not 4k in length";
    }
}

# Have to calculate what the final size WOULD BE once the payload
# (the binary to be signed) is attached, then update the header
# with that size.
#    THEN, attach the binary to the signed container later. Trying
# to update the size in the container after that payload binary
# is attached will remove the attached binary.
if ($g_var{input_final_cont_size}) {
  if ($g_var{verbose}) {
      print "Total container size, $g_var{input_final_cont_size} was passed in. It will be updated into the header\n";
  }
  $g_cmdParms = "--fldname container-size --fldvalue $g_var{input_final_cont_size}";
} else {
  # go with the size that we calculated
  $g_cmdParms = "--fldname container-size --fldvalue $containerSize";
}
updateContainer($g_cmdParms);

if ($g_var{attachPayloads}) {
    # NOW really attach the binary to the final header
    attachBinaryToContainer(finalContainer => $g_var{signed_container_name},
                            protected      => $g_var{protected_payload},
                            unprotected    => $g_var{unprotected_payload},
                            outfile        => $tmpFinalContainer,
                            createFinal    => 1);
}

print "\n$g_var{signed_container_name} created/updated\n";
my $timest = `stat -c %z $g_var{signed_container_name}`;
if ($?) {
    die "ERROR: Could not retrieve time stamp on $g_var{signed_container_name}";
}
print "Create time: $timest\n" if $g_var{verbose};

exit 0;

#############################################################
#
#  Subroutines
#
############################################################

#
# Verify the existence and relationships of the input parameters.
#  This should do verification of only the things that the
# signtool doesn't (and likely, shouldn't do), such as making
# sure we have the right number of keys.
#
sub verifyParms {

    if ($g_var{signing_mode} and
        ( ($g_var{signing_mode} eq "development") or
          ($g_var{signing_mode} eq "production")) ) {
       # then ok
    } else {
        die "-mode must be 'production' or 'development'\n";
    }

    if (!(exists($g_var{createAkeyPair})) and
        !(exists($g_var{protected_payload}))) {
        die "You must specify either --protectedPayload OR the --createKey option to create a key pair";
    } elsif ($g_var{createAkeyPair} and $g_var{protected_payload}) {
        die "You may not specify both --protectedPayload and --createKey";
    }
    # Called only to create a key pair
    if ($g_var{createAkeyPair}) {
        if (!$g_var{newPrivKeyPath}) {
            die "Path to private key file to be generated is required";
        }
        if (!$g_var{newPubKeyPath}) {
            die "Path to public key file to be generated is required";
        }
    } else {
        if (!(-e "$g_var{protected_payload}")) {
            die "Protected payload, $g_var{protected_payload}, is not found";
        }
    }

    if ($g_var{createContainer}) {
      # 3 hardware private keys are required
      if (!$g_var{HWprivKeyA}) {
        die "Hardware private key A required\n";
      } elsif  (!(-e $g_var{HWprivKeyA})) {
        die "Hardware signing key A, $g_var{HWprivKeyA}, not found\n";
      }
      if (!$g_var{HWprivKeyB}) {
        die "Hardware private key B required\n";
      } elsif  (!(-e $g_var{HWprivKeyB})) {
        die "Hardware signing key B, $g_var{HWprivKeyB}, not found\n";
      }
      if (!$g_var{HWprivKeyC}) {
        die "Hardware private key C required\n";
      } elsif  (!(-e $g_var{HWprivKeyC})) {
        die "Hardware signing key C, $g_var{HWprivKeyC}, not found\n";
      }
      # 1 software private key is required
      if (!$g_var{SWprivKeyP}) {
        die "Software private key P required\n";
      } elsif  (!(-e $g_var{SWprivKeyP})) {
        die "Software signing key P,$g_var{SWprivKeyP}, not found\n";
      } else {
        $g_var{in_swKeyCount}++;
      }

      # Validate the existence of the optional keys, Q and R, if
        # specified
      if ($g_var{SWprivKeyQ}) {
        $g_var{in_swKeyCount}++;
        if (!(-e $g_var{SWprivKeyQ})) {
          die "FW signing key Q,$g_var{SWprivKeyQ}, not found\n";
        }
      }
      if ($g_var{SWprivKeyR}) {
        $g_var{in_swKeyCount}++;
        if (!(-e $g_var{SWprivKeyR})) {
          die "FW signing key R,$g_var{SWprivKeyR}, not found\n";
        }
      }
    }
    if ($g_var{unprotected_payload}) {
        if (!(-e "$g_var{unprotected_payload}")) {
            die "$g_var{unprotected_payload} not found\n";
        }
    }

    # outfile is required
    if (!$g_var{signed_container_name}) {
        die "Output file (-out) is required\n";
    } elsif (!$g_var{createContainer}) {
        if (!(-e "$g_var{signed_container_name}")) {
            die "$g_var{signed_container_name} not found";
        }
    }
}

#
# Call the sign utility to create a key pair
sub createKeyPair {
    my %data        = @_;
    my $privKeyPath = $data{privKeyPath} || "";
    my $pubKeyPath  = $data{pubKeyPath}  || "";

    my $keyDir      = $data{keyDir}      || "";
    my $newPrivKey  = $data{privKeyName} || "";
    my $newPubKey   = $data{pubKeyName}  || "";
    my $verbose     = $data{verbose}     || 0;

    if (!$privKeyPath and !($keyDir && $newPrivKey)) {
        confess "createKeyPair: privKeyPath (full path) or keyDir, privKeyName (dir, file) are required";
    }
    if ($privKeyPath) {
        $keyDir = dirname($privKeyPath);
    } else {
        $privKeyPath = $keyDir . "/$newPrivKey";
        $pubKeyPath  = $keyDir . "/$newPubKey";
    }

    print "\n\nCalling $g_var{signutility} to create an EC 521 Curve Keypair.\n" if $verbose;
    if (!(-e "$keyDir")) {
      system("mkdir -p $keyDir");
      if ($?) {
          die "ERROR: createKeyPair unable to create directory, $keyDir";
      }
    }
    $g_CMD = "$g_var{signutility} --mode $g_var{signing_mode} --create_key --privkeyfile $privKeyPath --pubkeyfile $pubKeyPath";
    system($g_CMD);
    if ($?) {
       die "ERROR: Creation of a keypair failed";
    }
    print "New private and public keys have been created now in $keyDir\n" if $verbose;
    return 0, "";
}
#
# Convert value to hexstring
sub convertValueToHexStr {
   my $invalue = shift;
   return sprintf("%x", $invalue);
}
#
# Validate that all chars in the string are
# valid hex chars
sub validHexCharStr {
    my $inhexstr = shift;
    if ($inhexstr =~ /^[\da-f]+\z/i) {
        return 1;
    } else {
        return 0;
    }
}

sub getSizeAndHash {
    my $binaryPathOrStr = shift;

    # Get the size of the binary or string that was passed in
    my $hexSize   = 0;
    my $decSize   = 0;
    my $hashValue = "";
    my $hashLen   = 0;

    if (-e "$binaryPathOrStr") {
      # if the value passed in is a file, then get the size
      $decSize  = `stat -c %s $binaryPathOrStr`;
      if ($?) {
        die "ERROR: getSizeAndHash failed on 'stat' of $binaryPathOrStr";
      }
    } else {
       # it must be just a string
       $decSize = length($binaryPathOrStr);
    }
    $hexSize = convertValueToHexStr($decSize);

    if (-e "$binaryPathOrStr") {
      my $tmphash = `$HASH_ALG $binaryPathOrStr`;
      if ($?) {
        die "ERROR: getSizeAndHash failed attempting to run $HASH_ALG on $binaryPathOrStr";
      }
      chomp($tmphash);
      my ($genhash, $item) = split(' ', $tmphash);
      my @tmpvals   = split(' ', $genhash);
      $hashValue = $tmpvals[0];
      $hashLen   = length($hashValue);

    } else {
      $hashValue = $HASH_FUNC->($binaryPathOrStr);
      $hashLen   = length($hashValue);
      print "Hash of string: '$hashValue'\n" if $g_var{verbose};
    }
    if ($g_var{verbose}) {
      print "getSizeAndHash returning:\n Size:$hexSize\n Hash:'$hashValue'\nHash value length:$hashLen\n";
    }
    return $decSize, $hexSize, $hashValue, $hashLen;
}


#
# Input to this is a hash of the binary to be signed, the key to
# use to do the signing and an outfile that is to receive the
# signature.
sub generateSignature {
    my %data           = @_;
    my $digestToBeSigned = $data{digestToSign} || confess "digest required";
    my $keyToUse         = $data{keyToUse}     || confess "key for signing the digest is required";
    my $tmp_sig_file     = $data{sigfile}      || confess "sigfile required";
    my $verbose          = $data{verbose}      || 0;

    ### TODO (production mode): Prod needs name of a project with
    ### associated key, dev could point to any key and dev users
    ### would not have a notion of a project.
    $g_var{projname_or_key} = "--projname $keyToUse";

    # basic validation - valid hex chars in the string?
    if (!(validHexCharStr($digestToBeSigned))) {
        die "ERROR: generateSignature received a digest containing non-hex characters (digest: '$digestToBeSigned')";
    }
    # length what we expect?
    my $actualLen = length($digestToBeSigned);
    my $expectedDigestLength = hexBytesPerHash * asciiCharPerHexByte;
    if ($actualLen != $expectedDigestLength) {
        die "ERROR: generateSignature expected a digest length of $expectedDigestLength, actual length is $actualLen for $digestToBeSigned";
    }
    # Sign the hash (digest) passed in and save the signature
    # value into the sigfile
    print  "generateSignature: Signing the digest \n" if $verbose;
    $g_CMD = "$g_var{signutility} --mode $g_var{signing_mode} --sign $g_var{projname_or_key} --sigfile $tmp_sig_file --digest $digestToBeSigned";
    system($g_CMD);
    if ($?) {
        die "ERROR: Signing the digest failed";
    }
    return;
}

#
# Accepts just the parms to build up and run the sign utility
sub updateContainer {
  my $parms   = shift;

  my $utilCmd = "$g_var{signutility} --mode $g_var{signing_mode} --imagefile $g_var{signed_container_name}  ";
  $utilCmd .= $parms;
  if ($g_var{verbose}) { print "$utilCmd\n"; }
  system($utilCmd);
  if ($?)  {
    die ( "'$utilCmd' failed to execute: $!\n" );
  } else {
      print "\nCommand:\n$utilCmd\nCompletion : OK\n" if ($g_var{verbose});
  }
}

#
# Get the current date in a couple of specific formats
sub getNowTime {
   my $format = shift || "Ymd_HMS";

   my $now = "";
   if ($format eq "Ymd_HMS") {
     $now = strftime "%Y%m%d_%H%M%S", localtime;
   } elsif ($format eq "Y-m-d H:M:S") {
     $now = strftime "%Y-%m-%d %H:%M:%S", localtime;
   }
   return $now;
}

#
# The hash value here is calculated over the prefix key
# header (excluding HW signatures and SW public keys) and
# signed by the hardware private keys.
sub signPrefixKeyHeaderDigest  {
    my %data = @_;
    my $digestToSign = $data{digestToSign} || confess "digest required";

    if ($g_var{verbose}) {
      print "\n#######################################################\n";
      print "### -------  Sign prefix key header   -------- ###\n\n";
    }

    print "digest to sign passed in: $digestToSign\n" if $g_var{verbose};

    # Sign the digest over the prefix key header (excluding HW
    # signatures and FW public keys) with the three hardware keys.
    my $hwsignA_tmp = "$g_tmpdir/hwsignA.bin";

    generateSignature(digestToSign => $digestToSign,
                  keyToUse     => $g_var{HWprivKeyA},
                  sigfile      => $hwsignA_tmp,
                  verbose      => $g_var{verbose});
    $g_hwsignA = $hwsignA_tmp;

    my $hwsignB_tmp = "$g_tmpdir/hwsignB.bin";
    generateSignature(digestToSign => $digestToSign,
                   keyToUse     => $g_var{HWprivKeyB},
                   sigfile      => $hwsignB_tmp,
                   verbose      => $g_var{verbose});
    $g_hwsignB = $hwsignB_tmp;

    my $hwsignC_tmp = "$g_tmpdir/hwsignC.bin";
    generateSignature(digestToSign => $digestToSign,
                   keyToUse     => $g_var{HWprivKeyC},
                   sigfile      => $hwsignC_tmp,
                   verbose      => $g_var{verbose});
    $g_hwsignC = $hwsignC_tmp;
}


#
# The hash value for this routine is calculated over the
# software header (excluding SW signatures).
sub signSoftwareHeaderDigest {
    my %data = @_;
    my $binaryHash = $data{hashToSign} || confess "hash required";

    if ($g_var{verbose}) {
      print "\n#############################################\n";
      print "### --- Sign the software header digest ---- ###\n\n";
    }
    # Sign the digest using each of the FW private
    # keys (up to 3 keys may be specified)
    my $SWsignP_tmp = "$g_tmpdir/swsignP.bin";

    generateSignature(digestToSign => $binaryHash,
                  keyToUse     => $g_var{SWprivKeyP},
                  sigfile      => $SWsignP_tmp,
                  verbose      => $g_var{verbose});
    $g_SWsignP = $SWsignP_tmp;

    if ($g_var{SWprivKeyQ}) {
        my $SWsignQ_tmp = "$g_tmpdir/swsignQ.bin";
        generateSignature(digestToSign => $binaryHash,
                   keyToUse     => $g_var{SWprivKeyQ},
                   sigfile      => $SWsignQ_tmp,
                   verbose      => $g_var{verbose});
        $g_SWsignQ = $SWsignQ_tmp;
    }

    if ($g_var{SWprivKeyR}) {
        my $SWsignR_tmp = "$g_tmpdir/swsignR.bin";
        generateSignature(digestToSign => $binaryHash,
                   keyToUse     => $g_var{SWprivKeyR},
                   sigfile      => $SWsignR_tmp,
                   verbose      => $g_var{verbose});
        $g_SWsignR = $SWsignR_tmp;
    }
}


# Update the hardware public keys and signatures into the
# hardware header.
sub HWkeyInfo {
    if ($g_var{verbose}) {
      print "\n#########################################################\n";
      print "### --  Add hardware public key data to container  -- ###\n\n";
    }

    # Set up the hardware key and signature fields
    print "Updating the hdw key A \n" if $g_var{verbose};
    updateContainer("--fldname hw-keya --fldvalue $g_HWpubKeyA");

    print "Updating the hdw key A signature\n" if $g_var{verbose};
    updateContainer("--fldname hw-signa --fldvalue $g_hwsignA");

    print "Updating the hdw key B \n" if $g_var{verbose};
    updateContainer("--fldname hw-keyb --fldvalue $g_var{HWpubKeyB}");

    print "Updating the hdw key B signature\n" if $g_var{verbose};
    updateContainer("--fldname hw-signb --fldvalue $g_hwsignB");

    print "Updating the hdw key C \n" if $g_var{verbose};
    updateContainer("--fldname hw-keyc --fldvalue $g_var{HWpubKeyC}");

    print "Updating the hdw key C signature\n" if $g_var{verbose};
    updateContainer("--fldname hw-signc --fldvalue $g_hwsignC");
}
#
# Update the FW public keys in the container
sub SWkeys {
    if ($g_var{verbose}) {
      print "\n#############################################################\n";
      print "### -------  Add FW public key data to container  -------- ###\n\n";
    }
    my$sw_key_count = 0;

    ## There should always be at least one FW public key - key P
    print "Updating the FW key P \n" if $g_var{verbose};
    updateContainer("--fldname sw-keyp --fldvalue $g_SWpubKeyP");
    $sw_key_count = 1;

    print "\n$g_var{signed_container_name} first set of fields updated\n" if $g_var{verbose};

    # Now set up the optional fields (the 2nd and 3rd FW public keys)
    print "\nUpdating the secondary FW public keys and signatures in the container\n" if $g_var{verbose};

    if ($g_var{SWprivKeyQ}) {
        print "Updating the FW key Q \n" if $g_var{verbose};
        updateContainer("--fldname sw-keyq --fldvalue $g_SWpubKeyQ");
        $sw_key_count++;
    }
    if ($g_var{SWprivKeyR}) {
        print "Updating the FW key R \n" if $g_var{verbose};
        updateContainer("--fldname sw-keyr --fldvalue $g_SWpubKeyR");
        $sw_key_count++;
    }
    if ( ($sw_key_count < 1) or ($sw_key_count > 3) ) {
        die "ERROR: Count of FW public keys must be between 1-3\n";
    }
}

#
# Update the FW signatures in the container
sub SWsigns {
    if ($g_var{verbose}) {
      print "\n#############################################################\n";
      print "### -------  Update FW signatures into container  -------- ###\n\n";
    }
    print "Updating the FW signature P signature\n" if $g_var{verbose};
    updateContainer("--fldname sw-signp --fldvalue $g_SWsignP");

    print "\n$g_var{signed_container_name} first set of fields updated\n" if $g_var{verbose};

    # Now set up the optional fields (the 2nd and 3rd FW keys)
    print "\nUpdating the secondary FW keys and signatures in the container\n" if $g_var{verbose};
    if ($g_var{SWprivKeyQ}) {
        print "Updating the FW signature Q data\n" if $g_var{verbose};
        updateContainer("--fldname sw-signq --fldvalue $g_SWsignQ");
    }
    if ($g_var{SWprivKeyR}) {
        print "Updating the FW signature R signature\n" if $g_var{verbose};
        updateContainer("--fldname sw-signr --fldvalue $g_SWsignR");
    }
}

#
# Concatenate the FW public keys into one binary blob,
# get the hash and size and return to caller
#
sub prepFWkeyBlob {
    #
    #  In the prefix key header, there is a field for hash
    # of protected payload - that is the digest
    # generated over the concatenation of the fw public
    # keys.
    my ($fwPubKeysSize, $fwKeysHash, $fwHashLen);

    # In development mode, manually pull out the
    # pub: key string from the public key(s) extracted
    # from the private key(s), chop off the first byte
    # (indicates the type of data coming afterwards
    #  and is typically x04), concatenate all those
    # bits and get a hash of the result.
    my $tmpPkey = "";

    # Start with P first, since there should always be
    # the one key sfw key P
    $tmpPkey = parseCharPubKeyToGetPubKeyStringToHash(
                 fwPrivKey  => $g_var{SWprivKeyP} );

    my $concatedKeyStr = $tmpPkey;

    # else we are ok, set up a temp file name, just in case
    # we have 2 more keys to process
    my $concatedPubKeyFilesToHash = "$g_tmpdir/concatedFwKeysToHash";

    my $tmpQkey = "";
    if ($g_var{SWprivKeyQ}) {
        $tmpQkey = parseCharPubKeyToGetPubKeyStringToHash(
                                fwPrivKey  => $g_var{SWprivKeyQ} );
        $concatedKeyStr .= $tmpQkey;
    }
    my $tmpRkey = "";
    if ($g_var{SWprivKeyR}) {
        $tmpRkey = parseCharPubKeyToGetPubKeyStringToHash(
                                fwPrivKey  => $g_var{SWprivKeyR} );
        $concatedKeyStr .= $tmpRkey;
    }
    (my $decSz, $fwPubKeysSize, $fwKeysHash, $fwHashLen) = getSizeAndHash($concatedKeyStr);

    print "prepFWkeyBlob: Returning fw public key(s) size: $fwPubKeysSize\n  hash: $fwKeysHash\nhash len: $fwHashLen\n" if $g_var{verbose};
    return $fwPubKeysSize, $fwKeysHash, $fwHashLen;
}

# Given a FW private key:
#   dump it as text to a file
#   parse that text file, looking for the character representation
#     of the public key (the strings x:y:z... follow 'pub:')
#   lump all those xyz... values into one char string
#   strip off the '04' at the start (to get 132 bytes)
#   convert the resulting string to binary
#   write it to a file
#
# There SHOULD be a better way to do this - via some
# magic openssl command...but we need to make progress...
# so need to revisit this once things are working...
sub parseCharPubKeyToGetPubKeyStringToHash {
    my %data = @_;
    my $fwPrivKey = $data{fwPrivKey}  || confess "FW private key file required";

    my $l_cmd = "openssl ec -in $fwPrivKey -text";
    print "\n*** Dump the fw private key $fwPrivKey as text: $l_cmd\n" if $g_var{verbose};
    my $keyText = `$l_cmd`;
    if ($?) {
        die "ERROR: parseCharPubKeyToGetPubKeyStringToHash failed on the call to openssl";
    }
    # Parse out the char key string that follows 'pub:' and
    # dump it to the hashablepubkey var (this will be the
    # format of the fw public key that we need to
    # hash (or concat and hash) and sign to come up with
    # the magic signature that matches what the ROM code
    # will validate against.
    my $hashAblePubKey = parsePubKeyTextOut($keyText);
    my $pubKeyLen = length($hashAblePubKey);

    if ($pubKeyLen != expectedHexPubKeyLen) {
       die "parseCharPubKeyToGetPubKeyStringToHash: ERROR: public key length, $pubKeyLen, is not the expected length";
    }
    return $hashAblePubKey;
}

# The container header contains the hardware public keys
# and software public keys. We need to get these public
# keys from the private keys that were passed in (in
# development mode, at least..)
sub extractPubKey {
   my %data = @_;
   my $mode          = $data{mode}    || confess "production or development mode required";
   my $privKeyFile   = $data{keyfile} || confess "key file required";
   my $tmpPubKeyFile = $data{outfile} || confess "output file required";

   my $cm = "";
   if ($mode eq "development") {
       # this returns something that can be sent to signtool to put into
       # the container...but the output file is huge
       $cm = "openssl ec -in $privKeyFile -pubout -out $tmpPubKeyFile";

       my $openssl = `which openssl`;
       if ($?) {
          die "ERROR: Could not find command, openssl";
       }
       chomp($openssl);
       print "extractPubKey using $openssl\n" if $g_var{verbose};
       system($cm);
       if ($?) {
         die "$openssl failed \n";
       } elsif ($g_var{verbose}) {
        print "public key extracted to $tmpPubKeyFile\n" if $g_var{verbose};
       }
   } else {
       # in production mode, call the signtool to extract the public
       # key
   }
}

# One subroutine to do all the public key extraction
# calls in one place
sub extractPubKeysFromPriv {
    my %data = @_;
    my $mode = $data{mode}  || confess "mode is required";
    my $hwA = $data{hwkeya} || confess "Hardware private key A required";
    my $hwB = $data{hwkeyb} || confess "Hardware private key B required";
    my $hwC = $data{hwkeyc} || confess "Hardware private key C required";

    my $swP = $data{swkeyp} || confess "Software private key P required";
    my $swQ = $data{swkeyq} || "";
    my $swR = $data{swkeyr} || "";

    # In development mode, use openssl to extract the
    # public key from the private.
    extractPubKey(  mode    => $mode,
                    keyfile => $hwA,
                    outfile => "$g_tmpdir/hwpubkeya");
    $g_HWpubKeyA = "$g_tmpdir/hwpubkeya";

    extractPubKey(  mode    => $mode,
                    keyfile => $hwB,
                    outfile => "$g_tmpdir/hwpubkeyb");
    $g_var{HWpubKeyB} = "$g_tmpdir/hwpubkeyb";

    extractPubKey(  mode    => $mode,
                    keyfile => $hwC,
                    outfile => "$g_tmpdir/hwpubkeyc");
    $g_var{HWpubKeyC} = "$g_tmpdir/hwpubkeyc";

    extractPubKey(  mode    => $mode,
                    keyfile => $swP,
                    outfile => "$g_tmpdir/swpubkeyp");
    $g_SWpubKeyP = "$g_tmpdir/swpubkeyp";

    if ($g_var{SWprivKeyQ}) {
        extractPubKey(  mode    => $mode,
                        keyfile => $swQ,
                        outfile => "$g_tmpdir/swpubkeyq");
        $g_SWpubKeyQ = "$g_tmpdir/swpubkeyq";
    }
    if ($g_var{SWprivKeyR}) {
        extractPubKey(  mode    => $mode,
                        keyfile => $swR,
                        outfile => "$g_tmpdir/swpubkeyr");
                        $g_SWpubKeyR = "$g_tmpdir/swpubkeyr";
    }
}

# To create a full signed container, the binary that we
# just signed should be appended to the end of the headers.
sub attachBinaryToContainer {
    my %data = @_;
    my $tmpFinalContainer = $data{outfile}        || confess "output file required";
    my $protected_bin     = $data{protected}      || confess "protected binary required";
    my $finalCont         = $data{finalContainer} || confess "final signed container path required";
    my $unprotected       = $data{unprotected}    || "";
    my $createFinal       = $data{createFinal}    || 0;

    my ($decSz, $containerSize, $containerHash, $containerLen) = getSizeAndHash($finalCont);
    print "before attaching binary to the end of the container, the container size of $finalCont was $containerSize\n" if $g_var{verbose};

    print "\nAttaching the protected payload, $protected_bin, (and if specified, the unprotected binary, $unprotected) to the end of the container to create a temp file, $tmpFinalContainer\n" if $g_var{verbose};
    $g_CMD = "cat $finalCont $protected_bin > $tmpFinalContainer";
    if ($unprotected) {
       $g_CMD = "cat $finalCont $protected_bin $unprotected > $tmpFinalContainer";
    }
    system($g_CMD);
    if ($?) {
       die "$g_CMD failed";
    }
    if ($createFinal) {
        print "\nNow move the temp file ($tmpFinalContainer) to the final signed container name ($finalCont)\n" if $g_var{verbose};
        $g_CMD = "mv $tmpFinalContainer $finalCont";
        system($g_CMD);
        if ($?) {
          die "$g_CMD failed. Unable to construct the final container\n";
        }
    }
}

sub parsePubKeyTextOut {
   my $keyTextVar = shift;

   my $keystring = "";
   print "parsePubKeyTextOut: parse the public key from the dump of the private\n" if $g_var{verbose};
   $keyTextVar =~ s%[\n, ]%%g;
   if ($keyTextVar =~ /pub:/ ) {
      $keyTextVar =~ /pub:(.*)ASN1/;
      $keystring = $1;
      $keystring =~ s%:%%g;
   }
   # strip off the first 2 chars ('04')
   my $len = length($keystring) - 1;
   if ($len <= 1) {
      die "ERROR: length of our parsed key is <= 1, this is invalid";
   }
   $keystring = substr($keystring, 2, $len);
   if ($len <= 1) {
      die "ERROR: length of our parsed key is <= 1, this is invalid";
   }
   print "parsePubKeyTextOut: converting my new string with the first 04 string stripped off ($keystring) to binary\n" if $g_var{verbose};
   my $binaryPublicKey = pack ("H*",$keystring);

   return $binaryPublicKey;
}


__END__

=head1 NAME

crtSignedContainer.pl

=head1 SYNOPSIS

crtSignedContainer.pl [options]

=head1 OPTIONS

=over 8

=item B<--help>

Print a brief help message and exits.

=item B<--man>

Prints the manual page and exits.




=item B<--createKey>

Create a FW key pair (using openssl)

=item B<--privKeyPath>

Fully-qualified path to file to contain private key

=item B<--pubKeyPath>

Fully-qualified path to file to contain public key



=item B<--protectedPayload>

Fully-qualified path to binary to be signed


=item B<--out>

Path to signed container to be created

=item B<--hwPrivKeyA>

Fully-qualified path to hardware private key A (required in development mode)

=item B<--hwPrivKeyB>

Fully-qualified path to hardware private key B (required in development mode))

=item B<--hwPrivKeyC>

Fully-qualified path to hardware private key C (required in development mode))

=item B<--swPrivKeyP>

Fully-qualified path to firmware private key P (required in development mode))


=item B<--update>

Update the existing container

=item B<--mode>

development or production
   (Only development mode supported initially)

=item B<--swPrivKeyQ>

Fully-qualified path to firmware private key Q

=item B<--swPrivKeyR>

Fully-qualified path to firmware private key R

=item B<--flags_fw_key_ind>

Flags (firmware key indicator - prefix key header)
  hex, formatted like 0x00000000


=item B<--code-start-offset>

Code start offset (software header)
  hex, formatted like 0x0000000000000000

=item B<--cont-size>

Total size of the container
  hex, formatted like 0x0000000000000000

=item B<--target-HRMOR>

Target HRMOR
  hex, formatted like 0x0000000000000000

=item B<--inst-start>

Instruction start stack pointer address
  hex, formatted like 0x0000000000000000

=item B<--unprotectedPayload>

File containing the unprotected payload

=item B<--noattach>

Do NOT attach the -protectedPayload <binary>
  (and optional -unprotectedPayload <binary>)
  to the end of the signed container


=item B<--tempdir>=DIRECTORY

Temporary workspace used only when signing a
  binary (files in this directory will not
  be removed upon exit).


=item B<--verbose>

Prints out details of internal workings

=back

=head1 DESCRIPTION

B<crtSignedContainer.pl> will allow the caller to do all
of the following in just one call:

- create a valid FW key pair via openssl

 OR
- create an empty container prefix header with defaults
  filled in
- get a hash of the binary to be signed for inclusion
  in the appropriate prefix key or firmware header
- concatenate the FW public key(s) and get a hash of
  the resulting file
- sign the hash of the prefix key header (which includes
  the hash of the firmware (FW) public keys) using
  each of the hardware private keys (to generate the
  3 hardware signatures)
- sign the hash of the protected payload (such as
  hostboot.bin) using each of the 1-3 FW
  private keys (to generate the 1-3 FW signatures)
- update the hardware header with the hardware
  public keys
- update the prefix key header with the FW keys
  and hardware signatures
- update the software header with the FW signature(s)
- attach the protected payload (if desired), producing
  a signed container object
- update other fields in the headers, such as final
  container size, target HRMOR, code start offset,
  etc
- attach the unprotected payload (if provided)

The sign 'utility' has parms for the field 'name' and
the associated value to be inserted into the binary. So,
for the multiple field/value combinations that must be
updated into the final signed container, it must be
called multiple times (once for each of the HW keys
and associated signatures, once for each of the SFW
keys and associated signatures, etc).

As part of the container, there are headers that consist
of 3 Hardware public Keys
      * HW-KeyA - Hardware Public Key A
      * HW-KeyB - Hardware Public Key B
      * HW-KeyC - Hardware Public Key C
3 corresponding Hardware Signatures
      * HW-SigA - Hardware Signature A
      * HW-SigB - Hardware Signature B
      * HW-SigC - Hardware Signature C

and 1 to 3 FW Keys (the number of keys used/required
depends on the settings for each 'project')
      * SW-KeyP - FW Public Key P
      * SW-KeyQ - FW Public Key Q
      * SW-KeyR - FW Public Key R
and the associated Software Signatures
      * SW-SigP - FW Signature P
      * SW-SigQ - FW Signature Q
      * SW-SigR - FW Signature R

The protected payload (the actual signed binary
'blob') is (optionally) appended to the container.
Same is true for the unprotected payload.

=cut
