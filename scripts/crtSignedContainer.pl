#!/usr/bin/env perl
#
# IBM_PROLOG_BEGIN_TAG
# This is an automatically generated prolog.
#
# $Source: scripts/crtSignedContainer.pl $
#
# OpenPOWER sb-signing-utils Project
#
# Contributors Listed Below - COPYRIGHT 2016S
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
# This script will allow the caller to either
# - create a valid FW key pair via openssl
#
# OR
#  - create a signed container
#
#############################################################

use strict;
use Carp;
use Cwd;
use Fatal;
use Pod::Usage;
use IO::File;
use POSIX qw(strftime);
use Getopt::Long qw(GetOptions);
use Digest::SHA qw(sha512_hex);

############
#
# Constants
#
############
use constant HEX_BYTES_PER_HASH       => 64;
use constant ASCII_CHAR_PER_HEX_BYTE  => 2;
use constant EXPECTED_HEX_PUB_KEY_LEN => 132;
use constant HEX_BYTES_PER_SIGNATURE  => 132;
use constant DEC4K                    => 4096;
use constant MIN_FW_KEYS              => 1;
use constant MAX_KEYS                 => 3;

# pre-defined values used to interact with the sign utility.
# There should always be, at least, a DEFAULTS section in
# the production config file that defines the hardware and
# firmware key projects for the HW and SW key types.
use constant FWtype         => "SW";
use constant HWtype         => "HW";
use constant PRODUCTION     => "production";
use constant DEVELOPMENT    => "development";

# tmp files created on calls to the sign utility
# will be created with these extensions
use constant SIGN_FILE_EXTENSION => ".sign";
use constant PUB_FILE_EXTENSION  => ".pub";

# hardware and firmware key ids
use constant HW_KEY_IDS => qw(a b c);
use constant FW_KEY_IDS => qw(p q r);

############
#
# Variables
#
############
my @g_hwKeyIDs = (HW_KEY_IDS)[0..2];
my @g_fwKeyIDs = (FW_KEY_IDS)[0..2];

my $HASH_ALG  = "sha512sum";
my $HASH_FUNC = \&sha512_hex;

my %g_HWprivKey = ();
my %g_FWprivKey = ();

my %g_var;
$g_var{signing_mode}      = DEVELOPMENT;

# only used when creating a key pair
$g_var{createAkeyPair}    = 0;
$g_var{createContainer}   = 1; # create container on each call
$g_var{verbose}           = 0;

# By default, the protected payload (and unprotected
# payload, if specified) is attached to the end of
# container object.
$g_var{attachPayloads} = 1;

# path to the sign tool/utility to call (used to validate
# that the Linux OS-supplied binary in /usr/bin is not
# at the top of the caller's $PATH)
$g_var{signutility} = `which signtool`;
chomp($g_var{signutility});

# Hashes to contain the names of the tmp files used
# in retrieving public keys and creating signatures
my %g_signatureTmpFiles  = ();
my %g_pubkeyFiles        = ();
my %g_devModeShortPubkey = ();

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

  'hwPrivKeyA:s'         => \$g_HWprivKey{a},
  'hwPrivKeyB:s'         => \$g_HWprivKey{b},
  'hwPrivKeyC:s'         => \$g_HWprivKey{c},

  'swPrivKeyP:s'         => \$g_FWprivKey{p},
  'swPrivKeyQ:s'         => \$g_FWprivKey{q},
  'swPrivKeyR:s'         => \$g_FWprivKey{r},

  'sign-project-FW-token:s' => \$g_var{sign_project_token},
  'sign-project-config:s'=> \$g_var{sign_project_config},

  'mode:s'               => \$g_var{signing_mode},

  'flags-fw-key-ind:s'  => \$g_var{flags_fw_key_ind},
  'code-start-offset:s' => \$g_var{code_start_offset},
  'cont-size:s'         => \$g_var{input_final_cont_size},
  'target-HRMOR:s'      => \$g_var{target_HRMOR},
  'inst-start:s'        => \$g_var{inst_start},

  'update'              => sub { $g_var{createContainer} = 0},
  'noattach'            => sub { $g_var{attachPayloads} = 0},

  'help'                => \$g_cfgHelp,
  'man'                 => \$g_cfgMan,
  'verbose'             => \$g_var{verbose} ) || pod2usage(-verbose => 0);

pod2usage(-verbose => 1) if $g_cfgHelp;
pod2usage(-verbose => 2) if $g_cfgMan;

# Trap all interrupts. Exit through subroutine to
# clean up temp files.
$SIG{'INT'}     = 'cleanExit';
$SIG{'HUP'}     = 'cleanExit';
$SIG{'ABRT'}    = 'cleanExit';
$SIG{'QUIT'}    = 'cleanExit';
$SIG{'TRAP'}    = 'cleanExit';
$SIG{'STOP'}    = 'cleanExit';
$SIG{'__DIE__'} = 'cleanExit';


############################################################
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

defineTempFileNames(mode => $g_var{signing_mode});

my ($hdrPayloadSize, $hdrPayloadHash, $hdrHashLen) = "";

# Prepare the public keys to be added to the signed
# container header(s)
extractPubKeysFromPriv( mode => $g_var{signing_mode} );

# Concatenate the FW keys into one string so their size
# and hash can be calculated
if ($g_var{verbose}) {
  print "\n###################################################################\n";
  print "### --------  Concat FW keys, get size and hash of it  -------- ###\n";
}
($hdrPayloadSize, $hdrPayloadHash, $hdrHashLen) = prepFWkeyBlob();

if ($g_var{verbose}) {
  print "*************************** Calculated FW key info:\n";
  print "FW key hash size  : $hdrPayloadSize\n";
  print "FW key hash       : $hdrPayloadHash\n";
  print "FW key(s) hash len: $hdrHashLen\n";
}

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
    print "Now update the prefix key header's protected payload size ($hdrPayloadSize) in the container\n";
}
# header's protected payload size must be the hex represenation of:
#  key length in bytes * number of FW public keys
if ($hdrPayloadSize) {
  if ( ($g_var{fwKeyCount} < MIN_FW_KEYS) or
       ($g_var{fwKeyCount} > MAX_KEYS)) {
    die "ERROR: The number of firmware keys should be between 1 and 3, actual number is $g_var{fwKeyCount}.";
  }
  my $verifySize = EXPECTED_HEX_PUB_KEY_LEN * $g_var{fwKeyCount};
  my $hexSize = convertValueToHexStr($verifySize);
  if ($hexSize != $hdrPayloadSize) {
    die "ERROR: Expected size for the 'header payload size'is $hexSize (decimal size, $verifySize). Actual size is $hdrPayloadSize. (Number of firmware keys: $g_var{fwKeyCount})";
  }
  $g_cmdParms = "--fldname hdr-payload-size --fldvalue $hdrPayloadSize";
  updateContainer($g_cmdParms);
} else {
  die "ERROR: Invalid header payload size.\n";
}

if ($hdrPayloadHash) {
  my $verifyHashLen   = length($hdrPayloadHash);
  my $hashShouldBeLen = HEX_BYTES_PER_HASH * ASCII_CHAR_PER_HEX_BYTE;
  if ($verifyHashLen != $hashShouldBeLen) {
    die "ERROR: The length of the header payload hash' should be $hashShouldBeLen. Actual value is $verifyHashLen";
  }

  print "\n*****  Update the 'hash of protected payload' value in the prefix key header\n" if $g_var{verbose};
  $g_cmdParms = "--fldname hdr-payload-hash --fldvalue $hdrPayloadHash ";
  updateContainer($g_cmdParms);
} else {
  die "ERROR: Invalid header payload hash value.\n";
}
# Update the FW public keys into the container
FWkeys();

###############
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
# Sign that digest using each of the hardware private keys
signPrefixKeyHeaderDigest(digestToSign => $hwPrefixHdrDigest);

# Update the hardware keys and signatures into the container
HWkeyInfo();

###############
#
#   Software header
#

# Calculate the size and hash of the binary that we are to sign
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
  # normalize values back to decimal (since the caller can
  # pass in '0xZZZ' or 'ZZZ') to allow for an easier comparison
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
# call <sign utility> to get a signature over the digest of the
# software header (excluding software signatures and padding)
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
# Finish up by updating the FW signatures, and (optionally)
# attaching the protected and unprotected payloads.

FWsigns();

# Attach the binary that we just created a signature for to make a temporary
# object so we can get what will be the size of the final container object.
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
    if ($decSz <= DEC4K) {
       # make sure final container will be > 4k ie, the payload
       # is actually greater than 0 bytes long
       die "ERROR: container size for $tmpFinalContainer is less than or equal to 4k";
    }
} else {
    # get the size of the container (the header) alone
    ($decSz, $containerSize, $containerHash, $contHashLen) = getSizeAndHash($g_var{signed_container_name});
    if ($decSz != DEC4K) {
       die "ERROR: $g_var{signed_container_name} is not 4k in length";
    }
}

# Have to calculate what the final size WOULD BE once the payload is
# attached, then update the header with that size. Updating the size
# in the container after the payload is attached will remove it.
if ($g_var{input_final_cont_size}) {
  if ($g_var{verbose}) {
      print "Total container size, $g_var{input_final_cont_size} was passed in. It will be updated into the header\n";
  }
  $g_cmdParms = "--fldname container-size --fldvalue $g_var{input_final_cont_size}";
} else {
  # no final size passed in by the caller
  $g_cmdParms = "--fldname container-size --fldvalue $containerSize";
}
updateContainer($g_cmdParms);

if ($g_var{attachPayloads}) {
    # attach the payload(s) to the final header
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
cleanExit();


#############################################################
#
#  Subroutines
#
############################################################

#
# Verify the existence and relationships of the input parameters.
sub verifyParms {

    if ($g_var{signing_mode} and
        ( ($g_var{signing_mode} eq DEVELOPMENT) or
          ($g_var{signing_mode} eq PRODUCTION)) ) {
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
     if ($g_var{signing_mode} eq DEVELOPMENT) {
      # 3 hardware private keys are required
      foreach my $id (@g_hwKeyIDs) {
        if (!$g_HWprivKey{$id}) {
          die "Hardware private key $id required\n";
        } elsif  (!(-e $g_HWprivKey{$id})) {
          die "Hardware signing key $id, $g_HWprivKey{$id}, not found\n";
        }
      }
      # 1 software private key is required
      foreach my $id (@g_fwKeyIDs) {
        if ($id eq "p") {
          if (!$g_FWprivKey{$id}) {
            die "Firmware private key $id required\n";
          }
        }
        if ($g_FWprivKey{$id}) {
           if (!(-e "$g_FWprivKey{$id}")) {
             die "'$g_FWprivKey{$id}' was not found\n";
           } else {
             $g_var{fwKeyCount}++;
           }
        }
      }
     } else {
       # production mode

       # token name to use for signing required
       if (!(exists($g_var{sign_project_token}))) {
          die "Signing project firmware token required\n";
       }
       # project config file required
       if (!(exists($g_var{sign_project_config}))) {
          die "Signing project configuration file required\n";
       } elsif (!(-e $g_var{sign_project_config})) {
         die "Signing project config file, $g_var{sign_project_config}, not found\n";
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
# Verify that all chars in the string are
# valid hex chars
sub validHexCharStr {
    my $inhexstr = shift;
    if ($inhexstr =~ /^[\da-f]+\z/i) {
        return 1;
    } else {
        return 0;
    }
}

# Populate our internal hashes with the names of the signature
# and public key files that we expect to get back from our
# calls to signtool
sub defineTempFileNames {
    my %data = @_;
    my $mode = $data{mode}        || confess "mode is required";

    my $tmpFilePrefix = "devTempFile";
    if ($g_var{sign_project_token}) {
       $tmpFilePrefix = $g_var{sign_project_token};
    }

    my @keychars = @g_hwKeyIDs;
    push(@keychars, @g_fwKeyIDs);
    foreach my $id (@keychars) {
      $g_signatureTmpFiles{$id}  = $tmpFilePrefix;
      $g_signatureTmpFiles{$id} .= "_" . $id . SIGN_FILE_EXTENSION;

      $g_pubkeyFiles{$id}        = $tmpFilePrefix;
      $g_pubkeyFiles{$id}        .= "_" . $id . PUB_FILE_EXTENSION;

     if ($mode eq DEVELOPMENT) {
        $g_devModeShortPubkey{$id}  = "HW_" . $id . "_shortPub_";
        $g_devModeShortPubkey{$id} .= $id . PUB_FILE_EXTENSION;
      }
    }
    # clean up any temp files that might be left from a prior run
    removeTmpFiles();
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
      print "Hash of string: $hashValue\n" if $g_var{verbose};
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
    my %data             = @_;
    my $digestToBeSigned = $data{digestToSign} || confess "digest required";
    my $keyOrProj        = $data{keyOrProj}    || confess "either a key or a production project name is required";
    my $tmp_sig_file     = $data{sigfile}      || "";
    my $signType         = $data{hdwOrFW}      || FWtype;
    my $verbose          = $data{verbose}      || 0;

    if ( ($g_var{signing_mode} eq DEVELOPMENT) and
         (!$tmp_sig_file) ) {
       confess "In development mode, a file must be defined to accept the generated signature\n";
    }
    # basic validation - valid hex chars in the string?
    if (!(validHexCharStr($digestToBeSigned))) {
        die "ERROR: generateSignature received a digest containing non-hex characters (digest: '$digestToBeSigned')";
    }
    # length what we expect?
    my $actualLen = length($digestToBeSigned);
    my $expectedDigestLength = HEX_BYTES_PER_HASH * ASCII_CHAR_PER_HEX_BYTE;
    if ($actualLen != $expectedDigestLength) {
        die "ERROR: generateSignature expected a digest length of $expectedDigestLength, actual length is $actualLen for $digestToBeSigned";
    }
    # Sign the hash (digest) passed in
    $g_CMD = "$g_var{signutility} --mode $g_var{signing_mode} --sign";

    if ($g_var{signing_mode} eq PRODUCTION) {
       #  To sign with the FW keys, the token defines which set of
       # projects/keys will be used to sign the digest. The keytype
       # must be set to HW or SW to indicate to the sign utility
       # what kind of keys to work with (HW or FW/SW)
       $g_CMD .= " --configfile $g_var{sign_project_config}";
       $g_CMD .= " --digest $digestToBeSigned";
       $g_CMD .= " --project $keyOrProj";
       $g_CMD .= " --keytype $signType";
       print "generateSignature: Signing the digest with $signType / $keyOrProj\n" if $verbose;

    } else {
      # development mode, pass the key to sign with
      $g_CMD .= " --projname $keyOrProj --sigfile $tmp_sig_file";
      $g_CMD .= " --digest $digestToBeSigned";
      print "generateSignature: Signing the digest with $keyOrProj\n" if $verbose;
    }
    print "\n$g_CMD\n" if $verbose;
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

  my $utilCmd  = "$g_var{signutility} --mode $g_var{signing_mode}";
     $utilCmd .= " --imagefile $g_var{signed_container_name} ";
  $utilCmd .= $parms;
  if ($g_var{verbose}) { print "$utilCmd\n"; }
  system($utilCmd);
  if ($?)  {
    die ( "'$utilCmd' failed to execute: $!\n" );
  } else {
      print "\nCompletion : OK\n\n" if ($g_var{verbose});
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
# header (excluding HW signatures and FW public keys) and
# signed by the hardware private keys.
sub signPrefixKeyHeaderDigest  {
    my %data = @_;
    my $digestToSign = $data{digestToSign} || confess "digest required";

    if ($g_var{verbose}) {
      print "\n#######################################################\n";
      print "### -------  Sign prefix key header   -------- ###\n\n";
    }

    print "Digest to sign passed in: $digestToSign\n" if $g_var{verbose};

    # Sign the digest over the prefix key header (excluding HW
    # signatures and FW public keys) with the three hardware keys.
    if ($g_var{signing_mode} eq PRODUCTION) {
      # just need to call once to sign with each key
      generateSignature(digestToSign => $digestToSign,
                        keyOrProj    => $g_var{sign_project_token},
                        hdwOrFW      => HWtype,
                        verbose      => $g_var{verbose});

    } else {
      # need to call once/key in dev mode
      foreach my $id (@g_hwKeyIDs) {
        generateSignature(digestToSign => $digestToSign,
                          keyOrProj    => $g_HWprivKey{$id},
                          hdwOrFW      => HWtype,
                          sigfile      => $g_signatureTmpFiles{$id},
                          verbose      => $g_var{verbose});
      }
    }
}

#
# The hash value for this routine is calculated over the
# software header (excluding FW signatures).
sub signSoftwareHeaderDigest {
    my %data = @_;
    my $binaryHash = $data{hashToSign} || confess "hash required";

    if ($g_var{verbose}) {
      print "\n#############################################\n";
      print "### --- Sign the software header digest ---- ###\n\n";
    }
    # Sign the digest using each of the FW private
    # keys (up to 3 keys may be specified)
    if ($g_var{signing_mode} eq PRODUCTION) {
        # only need to call once to get all the signatures for
        # a set of projects/keys
        generateSignature(digestToSign => $binaryHash,
                          keyOrProj    => $g_var{sign_project_token},
                          hdwOrFW      => FWtype,
                          verbose      => $g_var{verbose});
    } else {
       # need to call once / key in dev mode
       foreach my $id (@g_fwKeyIDs) {
         if (exists($g_FWprivKey{$id}) and (-e "$g_FWprivKey{$id}")) {
           generateSignature(digestToSign => $binaryHash,
                           keyOrProj      => $g_FWprivKey{$id},
                           hdwOrFW        => FWtype,
                           sigfile        => $g_signatureTmpFiles{$id},
                           verbose        => $g_var{verbose});
         }
        }
    }
}


# Update the hardware public keys and signatures into the
# hardware header.
sub HWkeyInfo {
    if ($g_var{verbose}) {
      print "\n#########################################################\n";
      print "### --  Add hardware public key data to container  -- ###\n\n";
    }
    foreach my $hwk (@g_hwKeyIDs) {
       print "Updating the hdw key $hwk \n" if $g_var{verbose};
       my $fldname = "hw-key" . $hwk;
       updateContainer("--fldname $fldname --fldvalue $g_pubkeyFiles{$hwk}");

       print "Updating the hdw signature $hwk \n" if $g_var{verbose};
       my $fldname = "hw-sign" . $hwk;
       updateContainer("--fldname $fldname --fldvalue $g_signatureTmpFiles{$hwk}");

    }
}
#
# Update the FW public keys in the container
sub FWkeys {
    if ($g_var{verbose}) {
      print "\n#############################################################\n";
      print "### -------  Add FW public key data to container  -------- ###\n\n";
    }
    foreach my $fwk (@g_fwKeyIDs) {
       if (-e "$g_pubkeyFiles{$fwk}") {
         print "Updating the fw key $fwk \n" if $g_var{verbose};
         my $fldname = "sw-key" . $fwk;
         updateContainer("--fldname $fldname --fldvalue $g_pubkeyFiles{$fwk}");
      }
    }
}

#
# Update the FW signatures in the container
sub FWsigns {
    if ($g_var{verbose}) {
      print "\n#############################################################\n";
      print "### -------  Update FW signatures into container  -------- ###\n\n";
    }
    foreach my $fwk (@g_fwKeyIDs) {
       if (-e "$g_signatureTmpFiles{$fwk}") {
         print "Updating the FW signature $fwk signature\n" if $g_var{verbose};
         my $fldname = "sw-sign" . $fwk;
         updateContainer("--fldname $fldname --fldvalue $g_signatureTmpFiles{$fwk}");
       }
    }
}

#
# Concatenate the FW public keys into one binary blob,
# get the hash and size and return to caller
#
sub prepFWkeyBlob {
    my ($fwPubKeysSize, $fwKeysHash, $fwHashLen);

    # In development mode, extract the public key string, chop off the
    # first byte (indicates the type of data coming afterwards and is
    # typically x04), concatenate the keys, get a hash of the result.
    my $concatedKeyStr = "";
    foreach my $fwID (@g_fwKeyIDs) {
      my $extractedPubkey = $g_pubkeyFiles{$fwID};
      if ($g_var{signing_mode} eq DEVELOPMENT) {
         $extractedPubkey = $g_devModeShortPubkey{$fwID};
      }
      # strip off first byte (x40) to get 132 char string
      if (-e "$extractedPubkey") {
        my $shortkeystr = getCharPubKey($extractedPubkey);
        $concatedKeyStr .= $shortkeystr;
      }
    }
    (my $decSz, $fwPubKeysSize, $fwKeysHash, $fwHashLen) = getSizeAndHash($concatedKeyStr);

    print "prepFWkeyBlob: Returning fw public key(s) size: $fwPubKeysSize\nDecimal size:$decSz\n  hash: $fwKeysHash\nhash len: $fwHashLen\n" if $g_var{verbose};
    return $fwPubKeysSize, $fwKeysHash, $fwHashLen;
}
# Get the 132-byte fw public key used in the concat/hash/sign of the
# digest of the protected payload (fw public keys)
sub getCharPubKey {
  my $publicKeyFile = shift;

  my $charKey = "";
  open(FILE, "<$publicKeyFile") or die "ERROR: cannot open $publicKeyFile";
  local $/;
  $charKey = <FILE>;
  close(FILE);

  return substr($charKey, 1);
}
# Retrieve the public key(s) in the format required for follow-on processing.
sub extractPubKey {
   my %data = @_;
   my $mode          = $data{mode}     || confess "signing mode required";
   my $privKeyFile   = $data{keyfile}  || "";
   my $keyProjName   = $data{keyproj}  || "";
   my $tmpPubKeyFile = $data{outfile}  || confess "output file required";
   my $shortKeyStrFile = $data{pubKeyStrFile} || "";

   if ($mode eq DEVELOPMENT) {
     if (!$privKeyFile) {  confess "private key file required"; }

     # dump the public key to a file to pass to the signtool to
     # update the *w_public_key_* fields in the container header
     my $cm = "openssl pkey -in $privKeyFile -pubout -out $tmpPubKeyFile";
     my $openssl = `which openssl`;
     if ($?) {
       die "ERROR: Could not find command, openssl";
     }
     chomp($openssl);
     print "--- extractPubKey using $openssl\n" if $g_var{verbose};
     print "$cm\n" if $g_var{verbose};
     system($cm);
     if ($?) {
       die "$openssl failed \n";
     } elsif ($g_var{verbose}) {
      print "public key extracted to $tmpPubKeyFile\n" if $g_var{verbose};
     }

     # Get the fw public key in a format that can be processed to
     # concat/hash/sign the digest of the fw key blob.
     if ($shortKeyStrFile and (-e "$privKeyFile")) {
       $g_CMD  = "$g_var{signutility} --get_pubkey --mode $mode";
       $g_CMD .= " --privkeyfile $privKeyFile --pubkeyfile $shortKeyStrFile ";
       print "\n\nRetrieve pub key command: $g_CMD\n" if $g_var{verbose};
       system($g_CMD);
       if ($?) {
         die "ERROR: Failed to retrieve the public key from $privKeyFile\n";
       }
      }
   }
}

# One subroutine to do all the public key extraction calls in one place
sub extractPubKeysFromPriv {
    my %data = @_;
    my $mode = $data{mode} || confess "mode is required";

    if ($mode eq DEVELOPMENT) {
      #  hardware keys
      foreach my $id (@g_hwKeyIDs) {
        extractPubKey(mode    => $mode,
                      keyfile => $g_HWprivKey{$id},
                      outfile => $g_pubkeyFiles{$id});
      }
      # firmware keys
      foreach my $id (@g_fwKeyIDs) {
         if ($g_FWprivKey{$id}) {
             extractPubKey(mode          => $mode,
                           keyfile       => $g_FWprivKey{$id},
                           outfile       => $g_pubkeyFiles{$id},
                           pubKeyStrFile => $g_devModeShortPubkey{$id}
                        );
         } 
       }
    } else {

      # call the sign utility to extract the public key(s)
      $g_CMD  = "$g_var{signutility} --get_pubkey --mode $g_var{signing_mode} ";
      $g_CMD .= "--keytype HW ";
      $g_CMD .= "--projecttoken $g_var{sign_project_token} ";
      $g_CMD .= "--configfile $g_var{sign_project_config} ";

      print "\n\nRetrieve pub key command: $g_CMD\n" if $g_var{verbose};
      system($g_CMD);
      if ($?) {
         die "ERROR: Failed to retrieve the HW public keys for $g_var{sign_project_token}\n";
      }
      $g_CMD  = "$g_var{signutility} --get_pubkey --mode $g_var{signing_mode} ";
      $g_CMD .= "--keytype SW ";
      $g_CMD .= "--projecttoken $g_var{sign_project_token} ";
      $g_CMD .= "--configfile $g_var{sign_project_config} ";


      print "\n\nRetrieve pub key command: $g_CMD\n" if $g_var{verbose};
      system($g_CMD);
      if ($?) {
         die "ERROR: Failed to retrieve the FW public keys for $g_var{sign_project_token}\n";
      }

      # since the keys are all defined via projects in the config
      # file, there needs to be a count of what pub key files
      # are created via the call to the sign utility
      foreach my $id (@g_fwKeyIDs) {
        if (-e "$g_pubkeyFiles{$id}") { $g_var{fwKeyCount}++; }
      }
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

#
# clean up temp files (if any are left from a prior run)
sub removeTmpFiles {
    foreach my $f (keys %g_signatureTmpFiles) {
       if (-e "$g_signatureTmpFiles{$f}") {
          system("rm -rf $g_signatureTmpFiles{$f}");
          if ($?) {
             print "ERROR on rm of $g_signatureTmpFiles{$f}\n";
          }
          print "Removing $g_signatureTmpFiles{$f}\n" if $g_var{verbose};
       }
    }
    foreach my $f (keys %g_pubkeyFiles) {
       if (-e "$g_pubkeyFiles{$f}") {
          system("rm -rf $g_pubkeyFiles{$f}");
          if ($?) {
             print "ERROR on rm of $g_pubkeyFiles{$f}\n";
          }
          print "Removing $g_pubkeyFiles{$f}\n" if $g_var{verbose};
       }
    }
    foreach my $f (keys %g_devModeShortPubkey) {
       if (-e "$g_devModeShortPubkey{$f}") {
          system("rm -rf $g_devModeShortPubkey{$f}");
          if ($?) {
             print "ERROR on rm of $g_devModeShortPubkey{$f}\n";
          }
          print "Removing $g_devModeShortPubkey{$f}\n" if $g_var{verbose};
       }
    }
}

#
# clean up temp files and exit
sub cleanExit {
    my $exitCode = $_[0];

    # If we got to this function by an interrupt/signal, then
    # exitCode will be set to a string value for the interrupt
    # Disable Interrupts.
    $SIG{'INT'}  = 'IGNORE';
    $SIG{'STOP'} = 'IGNORE';
    $SIG{'HUP'}  = 'IGNORE';
    $SIG{'ABRT'} = 'IGNORE';
    $SIG{'QUIT'} = 'IGNORE';
    $SIG{'TRAP'} = 'IGNORE';

    removeTmpFiles();

    if ($exitCode and
        $exitCode !~ m/^(INT|STOP|HUP|ABRT|QUIT|TRAP)$/) {
        print STDERR "\n\n$0 ended abnormally.\n";
        print STDERR "Reason:\n $exitCode\n";
        exit 1;
    } else {
        if ($exitCode) {
          print "\nNow Exiting on: $exitCode\n";
        } else {
          $exitCode = 0;
        }
    }
    exit $exitCode;
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


=item B<--sign-project-token>

Sign project token (required in production mode)

=item B<--sign-project-config>

Fully-qualified path to configuration file
defining the sign server location, 'tokens' and
associated project names to be used for signing
(required in production mode).


=item B<--hwPrivKeyA>

Fully-qualified path to hardware private key A (required
in development mode)

=item B<--hwPrivKeyB>

Fully-qualified path to hardware private key B (required
in development mode)

=item B<--hwPrivKeyC>

Fully-qualified path to hardware private key C (required
in development mode)

=item B<--swPrivKeyP>

Fully-qualified path to firmware private key P (required
in development mode)


Update the existing container

=item B<--mode>

development or production


=item B<--swPrivKeyQ>

Fully-qualified path to firmware private key Q
(optional and only allowed in development mode)

=item B<--swPrivKeyR>

Fully-qualified path to firmware private key R
(optional and only allowed in development mode)


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
and associated signatures, once for each of the FW
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

and 1 to 3 FW Keys (FW Public Key P is required)
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
