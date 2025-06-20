/* Copyright 2017 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#ifndef _AIX
#include <getopt.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <unistd.h>

#include "ccan/endian/endian.h"
#include "container.c"
#include "container.h"

#define CONTAINER_HDR 0
#define PREFIX_HDR 1
#define SOFTWARE_HDR 2

char *progname;

bool verbose = false;
bool debug = false;
int wrap = 100;

void usage(int status);

unsigned char *sha3_512(const unsigned char *data, size_t len, unsigned char *md)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	const EVP_MD* alg = EVP_sha3_512();
	uint32_t md_len = SHA512_DIGEST_LENGTH;
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(ctx, alg, NULL);
	EVP_DigestUpdate(ctx, data, len);
	EVP_DigestFinal_ex(ctx, md, &md_len);
	EVP_MD_CTX_destroy(ctx);
	return md;
#else
    return NULL;
#endif
}

void getPublicKeyRaw(ecc_key_t *pubkeyraw, char *inFile)
{
	EVP_PKEY* pkey;
	unsigned char pubkeyData[1 + 2 * EC_COORDBYTES];

	FILE *fp = fopen(inFile, "r");
	if (!fp)
		die(EX_NOINPUT, "Cannot open key file: %s: %s", inFile, strerror(errno));

	if ((pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL))) {
		debug_msg("File \"%s\" is a PEM private key", inFile);
		fclose(fp);
	} else {
		fclose(fp);
		fp = fopen(inFile, "r");
		if ((pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL))) {
			debug_msg("File \"%s\" is a PEM public key", inFile);
		}
		fclose(fp);
	}

	if (pkey) {
		EC_KEY *key;
		const EC_GROUP *ecgrp;
		const EC_POINT *ecpoint;
		BIGNUM *pubkeyBN;

		key = EVP_PKEY_get1_EC_KEY(pkey);
		if (!key)
			die(EX_SOFTWARE, "%s", "Cannot EVP_PKEY_get1_EC_KEY");

		ecgrp = EC_KEY_get0_group(key);
		if (!ecgrp)
			die(EX_SOFTWARE, "%s", "Cannot EC_KEY_get0_group");

		ecpoint = EC_KEY_get0_public_key(key);
		if (!ecpoint)
			die(EX_SOFTWARE, "%s", "Cannot EC_KEY_get0_public_key");

		pubkeyBN = EC_POINT_point2bn(ecgrp, ecpoint, POINT_CONVERSION_UNCOMPRESSED,
				NULL, NULL);
		BN_bn2bin(pubkeyBN, pubkeyData);

		BN_free(pubkeyBN);
		EC_KEY_free(key);
		EVP_PKEY_free(pkey);
	}
	else {
		/* The file is not a public or private key in PEM format. So we check if
		 * it is a p521 pubkey in RAW format, in which case it will be 133 bytes
		 * with a leading byte of 0x04, indicating an uncompressed key. */
		int fdin, r;
		struct stat s;
		void *infile = NULL;

		fdin = open(inFile, O_RDONLY);
		if (fdin <= 0)
			die(EX_NOINPUT, "Cannot open key file: %s: %s", inFile, strerror(errno));

		r = fstat(fdin, &s);
		if (r != 0)
			die(EX_NOINPUT, "Cannot stat key file: %s", inFile);

		if (s.st_size == 1 + 2 * EC_COORDBYTES) {
			infile = mmap(NULL, s.st_size, PROT_READ, MAP_PRIVATE, fdin, 0);
			if (infile == MAP_FAILED)
				die(EX_OSERR, "Cannot mmap file at fd: %d, size: %lu (%s)",
						fdin, s.st_size, strerror(errno));
		}
		close(fdin);

		if (!infile || (*(unsigned char*) infile != 0x04)) {
			die(EX_DATAERR,
					"File \"%s\" is not in expected format (private or public key in PEM, or public key RAW)",
					inFile);
		} else
			debug_msg("File \"%s\" is a RAW public key", inFile);

		memcpy(pubkeyData, infile, sizeof(ecc_key_t) + 1);
	}

	// Remove the leading byte
	memcpy(*pubkeyraw, &pubkeyData[1], sizeof(ecc_key_t));

	return;
}

int readBinaryFile(unsigned char *data,
		   size_t *length,
		   const char *filename)
{
	int sRc = 0;
	size_t sBytes = 0;

	FILE *sFile = fopen(filename, "rb");
	if (NULL == sFile)
	{
		printf("**** ERROR: Unable to open file : %s\n", filename);
		sRc = 1;
	}

	/* Verify we have enough space */
	if (0 == sRc)
	{
		sRc = fseek(sFile, 0, SEEK_END);
		if (-1 == sRc) {
			printf("**** ERROR : Unable to find end of : %s\n", filename);
			sRc = 1;
		}
	}

	if (0 == sRc)
	{
		long sLen = ftell(sFile);
		if (-1 == sLen)
		{
			printf("**** ERROR : Unable to determine length of %s\n", filename);
			sRc = 1;
		}
		else if (*length < (size_t)sLen)
		{
			printf("**** ERROR : Not enough space for contents of file E:%lu A:%lu : %s\n",
			       (size_t)sLen, *length, filename);
			sRc = 1;
		}
		else
		{
			*length = (size_t)sLen;
		}
	}

	if (0 == sRc)
	{
		fseek(sFile, 0, SEEK_SET);

		sBytes = fread(data, 1, *length, sFile);
		if (sBytes != *length)
		{
			printf("**** ERROR: Failure reading from file : %s\n", filename);
			sRc = 1;
		}
	}
	if (NULL != sFile) {
		if (fclose(sFile)) {
			printf("**** ERROR: Failure closing file : %s\n", filename);
			if (0 == sRc) sRc = 1;
		}
	}
	return sRc;
}


void getSigRaw(ecc_signature_t *sigraw, char *inFile)
{
	int fdin;
	struct stat s;
	void *infile;
	int r;

	fdin = open(inFile, O_RDONLY);
	if (fdin <= 0)
		die(EX_NOINPUT, "Cannot open sig file: %s: %s", inFile, strerror(errno));

	r = fstat(fdin, &s);
	if (r != 0)
		die(EX_NOINPUT, "Cannot stat sig file: %s", inFile);

	if (s.st_size == 0)
		die(EX_NOINPUT, "Sig file \"%s\" is empty, something's not right.",
				inFile);

	infile = mmap(NULL, s.st_size, PROT_READ, MAP_PRIVATE, fdin, 0);
	if (infile == MAP_FAILED)
		die(EX_OSERR, "Cannot mmap file at fd: %d, size: %lu (%s)", fdin,
				s.st_size, strerror(errno));

	close(fdin);

	if (s.st_size == 2 * EC_COORDBYTES) {
		/* The file is a p521 signature in RAW format. */
		debug_msg("File \"%s\" is a RAW signature", inFile);
		memcpy(sigraw, infile, sizeof(ecc_signature_t));
	}
	else {
		/* Assume the file is a p521 signature in DER format.
		 * Convert the DER to a signature object, then extract the RAW. */
		debug_msg("File \"%s\" is a DER signature", inFile);

		int rlen, roff, slen, soff;
		const BIGNUM *sr, *ss;
		unsigned char outbuf[2 * EC_COORDBYTES];

		ECDSA_SIG* signature = d2i_ECDSA_SIG(NULL,
				(const unsigned char **) &infile, 7 + 2 * EC_COORDBYTES);

		memset(&outbuf, 0, sizeof(outbuf));

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		ECDSA_SIG_get0(signature, &sr, &ss);
#else
		sr = signature->r;
		ss = signature->s;
#endif
		rlen = BN_num_bytes(sr);
		roff = 66 - rlen;
		BN_bn2bin(sr, &outbuf[roff]);

		slen = BN_num_bytes(ss);
		soff = 66 + (66 - slen);
		BN_bn2bin(ss, &outbuf[soff]);

		memcpy(sigraw, outbuf, sizeof(ecc_signature_t));

		ECDSA_SIG_free(signature);
	}
	return;
}

void writeHdr(void *hdr, const char *outFile, int hdr_type, int container_version)
{
	FILE *fp;
	int r, hdr_sz;
	unsigned char md_buf[SHA512_DIGEST_LENGTH];
	unsigned char *md = NULL;

	if (container_version == 3)
	{
		switch (hdr_type) {
                  case CONTAINER_HDR:
                    hdr_sz = SECURE_BOOT_HEADERS_V3_SIZE;
                    break;
                  case PREFIX_HDR:
                    hdr_sz = sizeof(ROM_prefix_header_v3_raw);
                    md = sha3_512(hdr, hdr_sz, md_buf);
                    verbose_print((char *) "PR header hash  = ", md_buf, sizeof(md_buf));
                    break;
                  case SOFTWARE_HDR:
                    hdr_sz = sizeof(ROM_sw_header_v3_raw);
                    md = sha3_512(hdr, hdr_sz, md_buf);
                    verbose_print((char *) "SW header hash  = ", md_buf, sizeof(md_buf));
                    break;
                  default:
                    die(EX_SOFTWARE, "Unknown header type (%d)", hdr_type);
                }
	}
	else if (container_version == 2)
	{
		switch (hdr_type) {
		  case CONTAINER_HDR:
		    hdr_sz = SECURE_BOOT_HEADERS_V2_SIZE;
		    break;
		  case PREFIX_HDR:
		    hdr_sz = sizeof(ROM_prefix_header_v2_raw);
		    md = sha3_512(hdr, hdr_sz, md_buf);
		    verbose_print((char *) "PR header hash  = ", md_buf, sizeof(md_buf));
		    break;
		  case SOFTWARE_HDR:
		    hdr_sz = sizeof(ROM_sw_header_v2_raw);
		    md = sha3_512(hdr, hdr_sz, md_buf);
		    verbose_print((char *) "SW header hash  = ", md_buf, sizeof(md_buf));
		    break;
		  default:
		    die(EX_SOFTWARE, "Unknown header type (%d)", hdr_type);
		}
	} else {
		switch (hdr_type) {
		  case CONTAINER_HDR:
		    hdr_sz = SECURE_BOOT_HEADERS_SIZE;
		    break;
		  case PREFIX_HDR:
		    hdr_sz = sizeof(ROM_prefix_header_raw);
		    md = SHA512(hdr, hdr_sz, md_buf);
		    verbose_print((char *) "PR header hash  = ", md_buf, sizeof(md_buf));
		    break;
		  case SOFTWARE_HDR:
		    hdr_sz = sizeof(ROM_sw_header_raw);
		    md = SHA512(hdr, hdr_sz, md_buf);
		    verbose_print((char *) "SW header hash  = ", md_buf, sizeof(md_buf));
		    break;
		  default:
		    die(EX_SOFTWARE, "Unknown header type (%d)", hdr_type);
		}
	}

	fp = fopen(outFile, "w");
	if (!fp)
		die(EX_CANTCREAT, "Cannot create output file: %s: %s", outFile,
				strerror(errno));

	r = fwrite((const void *) hdr, hdr_sz, 1, fp);
	fclose(fp);

	if (r != 1)
		die(EX_SOFTWARE, "Error writing header file: %s: %s", outFile,
				strerror(errno));

	debug_msg("Wrote %d bytes to %s", hdr_sz, outFile);

	if (md) {
		char *fn = malloc(strlen(outFile) + 8);

		// Write the message digest in binary.
		sprintf(fn, "%s.md.bin", outFile);

		fp = fopen(fn, "w");
		if (!fp)
			die(EX_CANTCREAT, "Cannot create output file: %s: %s", fn,
					strerror(errno));

		fwrite(md, SHA512_DIGEST_LENGTH, 1, fp);
		fclose(fp);

		// Write the message digest in hexascii.
		sprintf(fn, "%s.md", outFile);

		fp = fopen(fn, "w");
		if (!fp)
			die(EX_CANTCREAT, "Cannot create output file: %s: %s", fn,
					strerror(errno));

		for (int i = 0; i < SHA512_DIGEST_LENGTH; i++)
			fprintf(fp, "%02x", md[i]);

		fclose(fp);
		free(fn);
	}
	return;
}

__attribute__((__noreturn__)) void usage (int status)
{
	if (status != 0) {
		fprintf(stderr, "Try '%s --help' for more information.\n", progname);
	}
	else {
		printf("Usage: %s [options]\n", progname);
		printf(
			"\n"
			"Options:\n"
			" -h, --help              display this message and exit\n"
			" -v, --verbose           show verbose output\n"
			"     --debug             show additional debug output\n"
			" -w, --wrap              column to wrap long output in verbose mode\n"
			" -a, --hw_key_a          file containing HW key A key in PEM or RAW format\n"
			" -b, --hw_key_b          file containing HW key B key in PEM or RAW format\n"
			" -c, --hw_key_c          file containing HW key C key in PEM or RAW format\n"
			"     --hw_key_d          file containing HW key D key in PEM or RAW format\n"
			" -p, --sw_key_p          file containing SW key P key in PEM or RAW format\n"
			" -q, --sw_key_q          file containing SW key Q key in PEM or RAW format\n"
			" -r, --sw_key_r          file containing SW key R key in PEM or RAW format\n"
			"     --sw_key_s          file containing SW key S key in PEM or RAW format\n"
			" -A, --hw_sig_a          file containing HW key A signature in DER format\n"
			" -B, --hw_sig_b          file containing HW key B signature in DER format\n"
			" -C, --hw_sig_c          file containing HW key C signature in DER format\n"
			"     --hw_sig_d          file containing HW key D signature in DER format\n"
			" -P, --sw_sig_p          file containing SW key P signature in DER format\n"
			" -Q, --sw_sig_q          file containing SW key Q signature in DER format\n"
			" -R, --sw_sig_r          file containing SW key R signature in DER format\n"
			"     --sw_sig_s          file containing SW key S signature in DER format\n"
			" -l, --payload           file containing the payload to be signed\n"
			" -I, --imagefile         file to write containerized image (output)\n"
			" -o, --hw-cs-offset      code start offset for prefix header in hex\n"
			" -O, --sw-cs-offset      code start offset for software header in hex\n"
			" -f, --hw-flags          prefix header flags in hex\n"
			" -F, --sw-flags          software header flags in hex\n"
			" -L, --label             character field up to 8 bytes, written to SW header\n"
			"     --dumpPrefixHdr     file to dump Prefix header blob (to be signed)\n"
			"     --dumpSwHdr         file to dump Software header blob (to be signed)\n"
			"     --dumpContrHdr      file to dump full Container header (w/o payload)\n"
			"     --security-version  Integer, sets the security version container field\n"
			" -V, --container-version Container version to generate (1, 2, 3)\n"
			"Note:\n"
			"- Keys A,B,C,P,Q,R must be valid p521 ECC keys. Keys may be provided as public\n"
			"  or private key in PEM format, or public key in uncompressed raw format.\n"
			"- Keys D,S must be valid Dilithium r2 8/7 keys. Keys may be provided as public\n"
			"  or private key in PEM format, or public key in uncompressed raw format.\n"
			"\n");
	};
	exit(status);
}

#ifndef _AIX
static struct option const opts[] = {
	{ "help",             no_argument,       0,  'h' },
	{ "verbose",          no_argument,       0,  'v' },
	{ "debug",            no_argument,       0,  'd' },
	{ "wrap",             required_argument, 0,  'w' },
	{ "hw_key_a",         required_argument, 0,  'a' },
	{ "hw_key_b",         required_argument, 0,  'b' },
	{ "hw_key_c",         required_argument, 0,  'c' },
	{ "hw_key_d",         required_argument, 0,  '[' },
	{ "sw_key_p",         required_argument, 0,  'p' },
	{ "sw_key_q",         required_argument, 0,  'q' },
	{ "sw_key_r",         required_argument, 0,  'r' },
	{ "sw_key_s",         required_argument, 0,  ']' },
	{ "hw_sig_a",         required_argument, 0,  'A' },
	{ "hw_sig_b",         required_argument, 0,  'B' },
	{ "hw_sig_c",         required_argument, 0,  'C' },
	{ "hw_sig_d",         required_argument, 0,  '{' },
	{ "sw_sig_p",         required_argument, 0,  'P' },
	{ "sw_sig_q",         required_argument, 0,  'Q' },
	{ "sw_sig_r",         required_argument, 0,  'R' },
	{ "sw_sig_s",         required_argument, 0,  '}' },
	{ "payload",          required_argument, 0,  'l' },
	{ "imagefile",        required_argument, 0,  'I' },
	{ "hw-cs-offset",     required_argument, 0,  'o' },
	{ "sw-cs-offset",     required_argument, 0,  'O' },
	{ "hw-flags",         required_argument, 0,  'f' },
	{ "sw-flags",         required_argument, 0,  'F' },
	{ "label",            required_argument, 0,  'L' },
	{ "dumpContrHdr",     required_argument, 0,  '0' },
	{ "dumpPrefixHdr",    required_argument, 0,  '1' },
	{ "dumpSwHdr",        required_argument, 0,  '2' },
	{ "security-version", required_argument, 0,  'S' },
	{ "container-version",required_argument, 0,  'V' },
    { "fw-ecid",          required_argument, 0,  '3' },
	{ NULL, 0, NULL, 0 }
};
#endif

static struct {
	char *hw_keyfn_a;
	char *hw_keyfn_b;
	char *hw_keyfn_c;
	char *hw_keyfn_d;
	char *sw_keyfn_p;
	char *sw_keyfn_q;
	char *sw_keyfn_r;
	char *sw_keyfn_s;
	char *hw_sigfn_a;
	char *hw_sigfn_b;
	char *hw_sigfn_c;
	char *hw_sigfn_d;
	char *sw_sigfn_p;
	char *sw_sigfn_q;
	char *sw_sigfn_r;
	char *sw_sigfn_s;
	char *imagefn;
	char *payloadfn;
	char *hw_cs_offset;
	char *sw_cs_offset;
	char *hw_flags;
	char *sw_flags;
    char* fw_ecid;
	char *label;
	char *prhdrfn;
	char *swhdrfn;
	char *cthdrfn;
	uint8_t security_version;
	uint8_t container_version;
} params;


int main(int argc, char* argv[])
{
	int fdout;
	unsigned int size, offset;
	void *container = malloc(SECURE_BOOT_HEADERS_V2_SIZE);
	char *buf = malloc(SECURE_BOOT_HEADERS_V2_SIZE);
	struct stat payload_st;
	void *infile = NULL;
	int r;
	ROM_container_raw *c = (ROM_container_raw*) container;
	ROM_prefix_header_raw *ph;
	ROM_prefix_data_raw *pd;
	ROM_sw_header_raw *swh;
	ROM_sw_sig_raw *ssig;
	ROM_container_v2_raw *c_v2 = (ROM_container_v2_raw*) container;
	ROM_prefix_header_v2_raw *ph_v2;
	ROM_prefix_data_v2_raw *pd_v2;
	ROM_sw_header_v2_raw *swh_v2;
	ROM_sw_sig_v2_raw *ssig_v2;
	ROM_container_v3_raw *c_v3 = (ROM_container_v3_raw*) container;
        ROM_prefix_header_v3_raw *ph_v3;
        ROM_prefix_data_v3_raw *pd_v3;
        ROM_sw_header_v3_raw *swh_v3;
        ROM_sw_sig_v3_raw *ssig_v3;

	unsigned char md[SHA512_DIGEST_LENGTH];
	void *p;
	ecc_key_t pubkeyraw;
	ecc_signature_t sigraw;

	progname = strrchr(argv[0], '/');
	if (progname != NULL)
		++progname;
	else
		progname = argv[0];

	memset(container, 0, SECURE_BOOT_HEADERS_V2_SIZE);

	// Set the default values for non-pointer optional args
	params.security_version = 0;
	params.container_version = 1;

#ifdef _AIX
	for (int i = 1; i < argc; i++) {
		if (!strcmp(*(argv + i), "--help")) {
			*(argv + i) = "-h";
		} else if (!strcmp(*(argv + i), "--verbose")) {
			*(argv + i) = "-v";
		} else if (!strcmp(*(argv + i), "--debug")) {
			*(argv + i) = "-4";
		} else if (!strcmp(*(argv + i), "--wrap")) {
			*(argv + i) = "-w";
		} else if (!strcmp(*(argv + i), "--hw_key_a")) {
			*(argv + i) = "-a";
		} else if (!strcmp(*(argv + i), "--hw_key_b")) {
			*(argv + i) = "-b";
		} else if (!strcmp(*(argv + i), "--hw_key_c")) {
			*(argv + i) = "-c";
		} else if (!strcmp(*(argv + i), "--hw_key_d")) {
			*(argv + i) = "-[";
		} else if (!strcmp(*(argv + i), "--sw_key_p")) {
			*(argv + i) = "-p";
		} else if (!strcmp(*(argv + i), "--sw_key_q")) {
			*(argv + i) = "-q";
		} else if (!strcmp(*(argv + i), "--sw_key_r")) {
			*(argv + i) = "-r";
		} else if (!strcmp(*(argv + i), "--sw_key_s")) {
			*(argv + i) = "-]";
		} else if (!strcmp(*(argv + i), "--hw_sig_a")) {
			*(argv + i) = "-A";
		} else if (!strcmp(*(argv + i), "--hw_sig_b")) {
			*(argv + i) = "-B";
		} else if (!strcmp(*(argv + i), "--hw_sig_c")) {
			*(argv + i) = "-C";
		} else if (!strcmp(*(argv + i), "--hw_sig_d")) {
			*(argv + i) = "-{";
		} else if (!strcmp(*(argv + i), "--sw_sig_p")) {
			*(argv + i) = "-P";
		} else if (!strcmp(*(argv + i), "--sw_sig_q")) {
			*(argv + i) = "-Q";
		} else if (!strcmp(*(argv + i), "--sw_sig_r")) {
			*(argv + i) = "-R";
		} else if (!strcmp(*(argv + i), "--sw_sig_s")) {
			*(argv + i) = "-}";
		} else if (!strcmp(*(argv + i), "--payload")) {
			*(argv + i) = "-l";
		} else if (!strcmp(*(argv + i), "--imagefile")) {
			*(argv + i) = "-I";
		} else if (!strcmp(*(argv + i), "--hw-cs-offset")) {
			*(argv + i) = "-o";
		} else if (!strcmp(*(argv + i), "--sw-cs-offset")) {
			*(argv + i) = "-O";
		} else if (!strcmp(*(argv + i), "--hw-flags")) {
			*(argv + i) = "-f";
		} else if (!strcmp(*(argv + i), "--sw-flags")) {
			*(argv + i) = "-F";
		} else if (!strcmp(*(argv + i), "--label")) {
			*(argv + i) = "-L";
		} else if (!strcmp(*(argv + i), "--dumpContrHdr")) {
			*(argv + i) = "-0";
		} else if (!strcmp(*(argv + i), "--dumpPrefixHdr")) {
			*(argv + i) = "-1";
		} else if (!strcmp(*(argv + i), "--dumpSwHdr")) {
			*(argv + i) = "-2";
		} else if (!strcmp(*(argv + i), "--security-version")) {
			*(argv + i) = "-S";
		} else if (!strcmp(*(argv + i), "--container-version")) {
			*(argv + i) = "-V";
		} else if (!strncmp(*(argv + i), "--", 2)) {
			fprintf(stderr, "%s: unrecognized option \'%s\'\n", progname,
					*(argv + i));
			usage(EX_OK);
		}
	}
#endif

	while (1) {
		int opt;
#ifdef _AIX
		opt = getopt(argc, argv, "?hvdw:a:b:c:[:p:q:r:]:A:B:C:{:P:Q:R:}:3:L:I:o:O:f:F:l:0:1:2:3:S:V:");
#else
		opt = getopt_long(argc, argv,
				"hvdw:a:b:c:[:p:q:r:}:A:B:C:{:P:Q:R:}:3:L:I:o:O:f:F:l:0:1:2:3:S:V:", opts,
				NULL);
#endif
		if (opt == -1)
			break;

		switch (opt) {
		case 'h':
			usage(EX_OK);
			break;
		case '?':
			usage(EX_USAGE);
			break;
		case 'v':
			verbose = true;
			break;
		case 'd':
			debug = true;
			break;
		case 'w':
			wrap = atoi(optarg);
			wrap = (wrap < 2) ? INT_MAX : wrap;
			break;
		case 'a':
			params.hw_keyfn_a = optarg;
			break;
		case 'b':
			params.hw_keyfn_b = optarg;
			break;
		case 'c':
			params.hw_keyfn_c = optarg;
			break;
		case '[':
			params.hw_keyfn_d = optarg;
			break;
		case 'p':
			params.sw_keyfn_p = optarg;
			break;
		case 'q':
			params.sw_keyfn_q = optarg;
			break;
		case 'r':
			params.sw_keyfn_r = optarg;
			break;
		case ']':
			params.sw_keyfn_s = optarg;
			break;
		case 'A':
			params.hw_sigfn_a = optarg;
			break;
		case 'B':
			params.hw_sigfn_b = optarg;
			break;
		case 'C':
			params.hw_sigfn_c = optarg;
			break;
		  case '{':
			params.hw_sigfn_d = optarg;
			break;
		case 'P':
			params.sw_sigfn_p = optarg;
			break;
		case 'Q':
			params.sw_sigfn_q = optarg;
			break;
		case 'R':
			params.sw_sigfn_r = optarg;
			break;
		  case '}':
			params.sw_sigfn_s = optarg;
			break;
		case 'l':
			params.payloadfn = optarg;
			break;
		case 'I':
			params.imagefn = optarg;
			break;
		case 'o':
			params.hw_cs_offset = optarg;
			break;
		case 'O':
			params.sw_cs_offset = optarg;
			break;
		case 'f':
			params.hw_flags = optarg;
			break;
		case 'F':
			params.sw_flags = optarg;
			break;
		case 'L':
			params.label = optarg;
			break;
		case '1':
			params.prhdrfn = optarg;
			break;
		case '2':
			params.swhdrfn = optarg;
			break;
		case '3':
			params.fw_ecid = optarg;
			break;
		case '0':
			params.cthdrfn = optarg;
			break;
		  case 'S':
			  {
				  int value = atoi(optarg);
				  if(value < 0 || value >= 256)
				  {
					  die(EX_DATAERR, "security-version (%d) must fit into a 1-byte field", value);
				  }
				  else
				  {
					  params.security_version = (uint8_t)value;
				  }
				  break;
			  }
		  case 'V':
			  {
				  int value = atoi(optarg);
				  if(value < 0 || value >= 0x10000)
				  {
					  die(EX_DATAERR, "container-version (%d) must fit into a 2-byte field", value);
				  }
				  else
				  {
					  params.container_version = (uint8_t)value;
				  }
				  break;
			  }
		  default:
		    usage(EX_USAGE);
		}
	}

	if (params.payloadfn) {
		int fdin = open(params.payloadfn, O_RDONLY);
		if (fdin <= 0)
			die(EX_NOINPUT, "Cannot open payload file: %s", params.payloadfn);

		r = fstat(fdin, &payload_st);
		if (r != 0)
			die(EX_NOINPUT, "Cannot stat payload file: %s", params.payloadfn);

		if (payload_st.st_size > 0) {
			infile = mmap(NULL, payload_st.st_size, PROT_READ, MAP_PRIVATE,
				      fdin, 0);
			if (infile == MAP_FAILED)
				die(EX_OSERR, "Cannot mmap file at fd: %d, size: %lu (%s)",
				    fdin, payload_st.st_size, strerror(errno));
		}
		close(fdin);
	}

	if (params.container_version < 1 || params.container_version > 3)
	{
		die(EX_NOINPUT, "Invalid container version: %d", params.container_version);
	}
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    else if (params.container_version == 2)
    {
		die(EX_NOINPUT, "Invalid container version due to downlevel openssl version : %d", params.container_version);
    }
#endif

	if (!infile)
		payload_st.st_size = 0;

	fdout = open(params.imagefn, O_WRONLY | O_CREAT | O_TRUNC,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fdout <= 0)
		die(EX_CANTCREAT, "Cannot create output file: %s", params.imagefn);

	// Container creation starts here.
	if (params.container_version == 1)
	{
		c->magic_number = cpu_to_be32(ROM_MAGIC_NUMBER);
		c->version = cpu_to_be16(1);
		c->container_size = cpu_to_be64(SECURE_BOOT_HEADERS_SIZE + payload_st.st_size);
		c->target_hrmor = 0;
		c->stack_pointer = 0;
		memset(c->hw_pkey_a, 0, sizeof(ecc_key_t));
		memset(c->hw_pkey_b, 0, sizeof(ecc_key_t));
		memset(c->hw_pkey_c, 0, sizeof(ecc_key_t));
		if (params.hw_keyfn_a) {
			getPublicKeyRaw(&pubkeyraw, params.hw_keyfn_a);
			verbose_print((char *) "pubkey A = ", pubkeyraw, sizeof(pubkeyraw));
			memcpy(c->hw_pkey_a, pubkeyraw, sizeof(ecc_key_t));
		}
		if (params.hw_keyfn_b) {
			getPublicKeyRaw(&pubkeyraw, params.hw_keyfn_b);
			verbose_print((char *) "pubkey B = ", pubkeyraw, sizeof(pubkeyraw));
			memcpy(c->hw_pkey_b, pubkeyraw, sizeof(ecc_key_t));
		}
		if (params.hw_keyfn_c) {
			getPublicKeyRaw(&pubkeyraw, params.hw_keyfn_c);
			verbose_print((char *) "pubkey C = ", pubkeyraw, sizeof(pubkeyraw));
			memcpy(c->hw_pkey_c, pubkeyraw, sizeof(ecc_key_t));
		}
		p = SHA512(c->hw_pkey_a, sizeof(ecc_key_t) * 3, md);
		if (!p)
			die(EX_SOFTWARE, "%s", "Cannot get SHA512");
		verbose_print((char *) "HW keys hash = ", md, sizeof(md));

		ph = container + sizeof(ROM_container_raw);
		ph->ver_alg.version = cpu_to_be16(1);
		ph->ver_alg.hash_alg = 1;
		ph->ver_alg.sig_alg = 1;

		// Set code-start-offset.
		if (params.hw_cs_offset) {
			if (!isValidHex(params.hw_cs_offset, 4))
				die(EX_DATAERR, "%s",
				    "Invalid input for hw-cs-offset, expecting a 4 byte hexadecimal value");
			uint64_t data = 0;
			sscanf(params.hw_cs_offset, "%lx", &data);
			ph->code_start_offset = cpu_to_be64(data);
			verbose_msg("hw-cs-offset = %#010lx", data);
		} else {
			ph->code_start_offset = 0;
		}
		ph->reserved = 0;

		// Set flags.
		if (params.hw_flags) {
			if (!isValidHex(params.hw_flags, 4))
				die(EX_DATAERR, "%s",
				    "Invalid input for hw-flags, expecting a 4 byte hexadecimal value");
			uint32_t data;
			sscanf(params.hw_flags, "%x", &data);
			ph->flags = cpu_to_be32(data);
			verbose_msg("hw-flags = %#010x", data);
		} else {
			ph->flags = cpu_to_be32(0x80000000);
		}
		memset(ph->payload_hash, 0, sizeof(sha2_hash_t));
		ph->ecid_count = 0;

		pd = (ROM_prefix_data_raw*) ph->ecid;
		memset(pd->hw_sig_a, 0, sizeof(ecc_signature_t));
		memset(pd->hw_sig_b, 0, sizeof(ecc_signature_t));
		memset(pd->hw_sig_c, 0, sizeof(ecc_signature_t));

		// Write the HW signatures.
		if (params.hw_sigfn_a) {
			getSigRaw(&sigraw, params.hw_sigfn_a);
			verbose_print((char *) "signature A = ", sigraw, sizeof(sigraw));
			memcpy(pd->hw_sig_a, sigraw, sizeof(ecc_key_t));
		}
		if (params.hw_sigfn_b) {
			getSigRaw(&sigraw, params.hw_sigfn_b);
			verbose_print((char *) "signature B = ", sigraw, sizeof(sigraw));
			memcpy(pd->hw_sig_b, sigraw, sizeof(ecc_key_t));
		}
		if (params.hw_sigfn_c) {
			getSigRaw(&sigraw, params.hw_sigfn_c);
			verbose_print((char *) "signature C = ", sigraw, sizeof(sigraw));
			memcpy(pd->hw_sig_c, sigraw, sizeof(ecc_key_t));
		}
		memset(pd->sw_pkey_p, 0, sizeof(ecc_key_t));
		memset(pd->sw_pkey_q, 0, sizeof(ecc_key_t));
		memset(pd->sw_pkey_r, 0, sizeof(ecc_key_t));

		// Write the FW keys.
		if (params.sw_keyfn_p) {
			getPublicKeyRaw(&pubkeyraw, params.sw_keyfn_p);
			verbose_print((char *) "pubkey P = ", pubkeyraw, sizeof(pubkeyraw));
			memcpy(pd->sw_pkey_p, pubkeyraw, sizeof(ecc_key_t));
			ph->sw_key_count++;
		}
		if (params.sw_keyfn_q) {
			getPublicKeyRaw(&pubkeyraw, params.sw_keyfn_q);
			verbose_print((char *) "pubkey Q = ", pubkeyraw, sizeof(pubkeyraw));
			memcpy(pd->sw_pkey_q, pubkeyraw, sizeof(ecc_key_t));
			ph->sw_key_count++;
		}
		if (params.sw_keyfn_r) {
			getPublicKeyRaw(&pubkeyraw, params.sw_keyfn_r);
			verbose_print((char *) "pubkey R = ", pubkeyraw, sizeof(pubkeyraw));
			memcpy(pd->sw_pkey_r, pubkeyraw, sizeof(ecc_key_t));
			ph->sw_key_count++;
		}
		debug_msg("sw_key_count = %u", ph->sw_key_count);
		ph->payload_size = cpu_to_be64(ph->sw_key_count * sizeof(ecc_key_t));

		// Calculate the SW keys hash.
		p = SHA512(pd->sw_pkey_p, sizeof(ecc_key_t) * ph->sw_key_count, md);
		if (!p)
			die(EX_SOFTWARE, "%s", "Cannot get SHA512");
		memcpy(ph->payload_hash, md, sizeof(sha2_hash_t));
		verbose_print((char *) "SW keys hash = ", md, sizeof(md));

		// Dump the Prefix header.
		if (params.prhdrfn)
			writeHdr((void *) ph, params.prhdrfn, PREFIX_HDR, params.container_version);

		swh = (ROM_sw_header_raw*) (((uint8_t*) pd) + sizeof(ecc_signature_t) * 3
					    + be64_to_cpu(ph->payload_size));
		swh->ver_alg.version = cpu_to_be16(1);
		swh->ver_alg.hash_alg = 1;
		swh->ver_alg.sig_alg = 1;

		// Set code-start-offset.
		if (params.sw_cs_offset) {
			if (!isValidHex(params.sw_cs_offset, 4))
				die(EX_DATAERR, "%s",
				    "Invalid input for sw-cs-offset, expecting a 4 byte hexadecimal value");
			uint64_t data = 0;
			sscanf(params.sw_cs_offset, "%lx", &data);
			swh->code_start_offset = cpu_to_be64(data);
			verbose_msg("sw-cs-offset = %#010lx", data);
		} else {
			swh->code_start_offset = 0;
		}
		swh->reserved = 0;

		// Add component ID (label).
		if (params.label) {
			if (!isValidAscii(params.label, 0))
				die(EX_DATAERR, "%s",
				    "Invalid input for label, expecting a 8 char ASCII value");
			strncpy((char *) &swh->reserved, params.label, 8);
			verbose_msg("component ID (was reserved) = %.8s",
				    (char * ) &swh->reserved);
		}

		// Set flags.
		if (params.sw_flags) {
			if (!isValidHex(params.sw_flags, 4))
				die(EX_DATAERR, "%s",
				    "Invalid input for sw-flags, expecting a 4 byte hexadecimal value");
			uint32_t data;
			sscanf(params.sw_flags, "%x", &data);
			swh->flags = cpu_to_be32(data);
			verbose_msg("sw-flags = %#010x", data);
		} else {
			swh->flags = cpu_to_be32(0x00000000);
		}
		swh->security_version = params.security_version;
		swh->payload_size = cpu_to_be64(payload_st.st_size);

		// Calculate the payload hash.
		p = SHA512(infile, payload_st.st_size, md);
		if (!p)
			die(EX_SOFTWARE, "%s", "Cannot get SHA512");
		memcpy(swh->payload_hash, md, sizeof(sha2_hash_t));
		verbose_print((char *) "Payload hash = ", md, sizeof(md));

		// Dump the Software header.
		if (params.swhdrfn)
			writeHdr((void *) swh, params.swhdrfn, SOFTWARE_HDR, params.container_version);

		ssig = (ROM_sw_sig_raw*) (((uint8_t*) swh) + sizeof(ROM_sw_header_raw));
		memset(ssig->sw_sig_p, 0, sizeof(ecc_signature_t));
		memset(ssig->sw_sig_q, 0, sizeof(ecc_signature_t));
		memset(ssig->sw_sig_r, 0, sizeof(ecc_signature_t));

		// Write the HW signatures.
		if (params.sw_sigfn_p) {
			getSigRaw(&sigraw, params.sw_sigfn_p);
			verbose_print((char *) "signature P = ", sigraw, sizeof(sigraw));
			memcpy(ssig->sw_sig_p, sigraw, sizeof(ecc_key_t));
		}
		if (params.sw_sigfn_q) {
			getSigRaw(&sigraw, params.sw_sigfn_q);
			verbose_print((char *) "signature Q = ", sigraw, sizeof(sigraw));
			memcpy(ssig->sw_sig_q, sigraw, sizeof(ecc_key_t));
		}
		if (params.sw_sigfn_r) {
			getSigRaw(&sigraw, params.sw_sigfn_r);
			verbose_print((char *) "signature R = ", sigraw, sizeof(sigraw));
			memcpy(ssig->sw_sig_r, sigraw, sizeof(ecc_key_t));
		}

		// Dump the full container header.
		if (params.cthdrfn)
			writeHdr((void *) c, params.cthdrfn, CONTAINER_HDR, params.container_version);

		// Print container stats.
		size = (uint8_t*) ph - (uint8_t *) c;
		offset = 0;
		verbose_msg("HW header size        = %4u (%#06x) at offset %4u (%#06x)",
			    size, size, offset, offset);
		size = (uint8_t*) pd - (uint8_t *) ph;
		offset = (uint8_t*) ph - (uint8_t *) c;
		verbose_msg("Prefix header size    = %4u (%#06x) at offset %4u (%#06x)",
			    size, size, offset, offset);
		size = (uint8_t*) swh - (uint8_t *) pd;
		offset = (uint8_t*) pd - (uint8_t *) c;
		verbose_msg("Prefix data size      = %4u (%#06x) at offset %4u (%#06x)",
			    size, size, offset, offset);
		size = (uint8_t*) ssig - (uint8_t *) swh;
		offset = (uint8_t*) swh - (uint8_t *) c;
		verbose_msg("SW header size        = %4u (%#06x) at offset %4u (%#06x)",
			    size, size, offset, offset);
		size = sizeof(ecc_key_t) * ph->sw_key_count;
		offset = (uint8_t*) ssig - (uint8_t *) c;
		verbose_msg("SW signature size     = %4u (%#06x) at offset %4u (%#06x)",
			    size, size, offset, offset);

		verbose_msg("TOTAL HEADER SIZE     = %4d (%#0x)", SECURE_BOOT_HEADERS_SIZE,
			    SECURE_BOOT_HEADERS_SIZE);
		verbose_msg("PAYLOAD SIZE          = %4lu (%#0lx)",
			    be64_to_cpu(swh->payload_size), be64_to_cpu(swh->payload_size));
		verbose_msg("TOTAL CONTAINER SIZE  = %4lu (%#0lx)",
			    be64_to_cpu(c->container_size), be64_to_cpu(c->container_size));

		// Write container.
		if ((r = write(fdout, container, SECURE_BOOT_HEADERS_SIZE)) != 4096)
			die(EX_SOFTWARE, "Cannot write container header (r = %d) (%s)", r,
			    strerror(errno));


	} else if (params.container_version == 2) {
		// VERSION 2 CONTAINER

		c_v2->magic_number = cpu_to_be32(ROM_MAGIC_NUMBER);
		c_v2->version = cpu_to_be16(2);
		c_v2->container_size = cpu_to_be64(SECURE_BOOT_HEADERS_V2_SIZE + payload_st.st_size);
		memset(c_v2->hw_pkey_a, 0, sizeof(ecc_key_t));
		memset(c_v2->hw_pkey_d, 0, sizeof(dilithium_key_t));
		if (params.hw_keyfn_a) {
			getPublicKeyRaw(&pubkeyraw, params.hw_keyfn_a);
			verbose_print((char *) "pubkey A = ", pubkeyraw, sizeof(pubkeyraw));
			memcpy(c_v2->hw_pkey_a, pubkeyraw, sizeof(ecc_key_t));
		}
		if (params.hw_keyfn_d) {
			size_t sLen = sizeof(c_v2->hw_pkey_d);
			int r = readBinaryFile(c_v2->hw_pkey_d, &sLen,params.hw_keyfn_d);
			if (0 != r || sLen != DILITHIUM_PUB_KEY_LENGTH)
				die(EX_SOFTWARE, "Failure reading HW PUBKEY D : %s",params.hw_keyfn_d);
			verbose_print((char *) "pubkey D = ", c_v2->hw_pkey_d, sizeof(c_v2->hw_pkey_d));
		}
		p = sha3_512(c_v2->hw_pkey_a, sizeof(ecc_key_t) + sizeof(dilithium_key_t), md);
		if (!p)
			die(EX_SOFTWARE, "%s", "Cannot get SHA3-512");
		verbose_print((char *) "HW keys hash = ", md, sizeof(md));

		ph_v2 = (ROM_prefix_header_v2_raw*)&(c_v2->prefix);
		ph_v2->ver_alg.version = cpu_to_be16(2);
		ph_v2->ver_alg.hash_alg = 2;
		ph_v2->ver_alg.sig_alg = 2;
		ph_v2->reserved = 0;

		// Set flags.
		if (params.hw_flags) {
			if (!isValidHex(params.hw_flags, 4))
				die(EX_DATAERR, "%s",
				    "Invalid input for hw-flags, expecting a 4 byte hexadecimal value");
			uint32_t data;
			sscanf(params.hw_flags, "%x", &data);
			ph_v2->flags = cpu_to_be32(data);
			verbose_msg("hw-flags = %#010x", data);
		} else {
			ph_v2->flags = cpu_to_be32(0x80000000);
		}
		memset(ph_v2->payload_hash, 0, sizeof(sha2_hash_t));
		memset(ph_v2->ecid, 0, ECID_SIZE);
		memset(ph_v2->reserved2, 0, sizeof(ph_v2->reserved2));

		pd_v2 = (ROM_prefix_data_v2_raw*)&c_v2->prefix_data;
		memset(pd_v2->hw_sig_a, 0, sizeof(ecc_signature_t));
		memset(pd_v2->hw_sig_d, 0, sizeof(dilithium_signature_t));

		// Write the HW signatures.
		if (params.hw_sigfn_a) {
			getSigRaw(&sigraw, params.hw_sigfn_a);
			verbose_print((char *) "signature A = ", sigraw, sizeof(sigraw));
			memcpy(pd_v2->hw_sig_a, sigraw, sizeof(ecc_key_t));
		}
		if (params.hw_sigfn_d) {
			size_t sLen = sizeof(pd_v2->hw_sig_d);
			int r = readBinaryFile(pd_v2->hw_sig_d, &sLen,params.hw_sigfn_d);
			if (0 != r || sLen != DILITHIUM_SIG_LENGTH)
				die(EX_SOFTWARE, "Failure reading HW SIG D : %s",params.hw_sigfn_d);
			verbose_print((char *) "signature D = ", pd_v2->hw_sig_d, sizeof(pd_v2->hw_sig_d));
		}
		memset(pd_v2->sw_pkey_p, 0, sizeof(ecc_key_t));
		memset(pd_v2->sw_pkey_s, 0, sizeof(dilithium_key_t));

		// Write the FW keys.
		if (params.sw_keyfn_p) {
			getPublicKeyRaw(&pubkeyraw, params.sw_keyfn_p);
			verbose_print((char *) "pubkey P = ", pubkeyraw, sizeof(pubkeyraw));
			memcpy(pd_v2->sw_pkey_p, pubkeyraw, sizeof(ecc_key_t));
			ph_v2->sw_key_count++;
			ph_v2->payload_size += sizeof(ecc_key_t);
		}
		if (params.sw_keyfn_s) {
			size_t sLen = sizeof(pd_v2->sw_pkey_s);
			int r = readBinaryFile(pd_v2->sw_pkey_s, &sLen,params.sw_keyfn_s);
			if (0 != r || sLen != DILITHIUM_PUB_KEY_LENGTH)
				die(EX_SOFTWARE, "Failure reading SW PUBKEY S : %s",params.sw_keyfn_s);
			verbose_print((char *) "pubkey S = ", pd_v2->sw_pkey_s, sizeof(pd_v2->sw_pkey_s));
			ph_v2->sw_key_count++;
			ph_v2->payload_size += sizeof(dilithium_key_t);
		}
		ph_v2->payload_size = cpu_to_be64(ph_v2->payload_size);
		debug_msg("sw_key_count = %u", ph_v2->sw_key_count);

		// Calculate the SW keys hash.
		p = sha3_512(pd_v2->sw_pkey_p, be64_to_cpu(ph_v2->payload_size), md);
		if (!p)
			die(EX_SOFTWARE, "%s", "Cannot get SHA3-512");
		memcpy(ph_v2->payload_hash, md, sizeof(sha2_hash_t));
		verbose_print((char *) "SW keys hash = ", md, sizeof(md));

		// Dump the Prefix header.
		if (params.prhdrfn)
			writeHdr((void *) ph_v2, params.prhdrfn, PREFIX_HDR, params.container_version);

		swh_v2 = (ROM_sw_header_v2_raw*) &c_v2->swheader;
		swh_v2->ver_alg.version = cpu_to_be16(2);
		swh_v2->ver_alg.hash_alg = 2;
		swh_v2->ver_alg.sig_alg = 2;

		swh_v2->reserved = 0;

		// Add component ID (label).
		if (params.label) {
			if (!isValidAscii(params.label, 0))
				die(EX_DATAERR, "%s",
				    "Invalid input for label, expecting a 8 char ASCII value");
			strncpy((char *) &swh_v2->component_id, params.label, 8);
			verbose_msg("component ID = %.8s",
				    (char * ) &swh_v2->component_id);
		} else {
			swh_v2->component_id = 0;
		}

		// Set flags.
		if (params.sw_flags) {
			if (!isValidHex(params.sw_flags, 4))
				die(EX_DATAERR, "%s",
				    "Invalid input for sw-flags, expecting a 4 byte hexadecimal value");
			uint32_t data;
			sscanf(params.sw_flags, "%x", &data);
			swh_v2->flags = cpu_to_be32(data);
			verbose_msg("sw-flags = %#010x", data);
		} else {
			swh_v2->flags = cpu_to_be32(0x00000000);
		}
		swh_v2->security_version = params.security_version;
		swh_v2->payload_size = cpu_to_be64(payload_st.st_size);
		swh_v2->unprotected_payload_size = 0;

        // Set the FW ECID if provided
		memset(swh_v2->ecid, 0, ECID_SIZE);
		if (params.fw_ecid) {
			if (!isValidHex(params.fw_ecid, ECID_SIZE))
				die(EX_DATAERR, "%s",
				    "Invalid input for sw-ecid, expecting a 16 byte hexadecimal value");
			for (int x = 0; x < ECID_SIZE; x++) {
				sscanf(&(params.fw_ecid[x*2]), "%2hhx", &(swh_v2->ecid[x]));
			}
			verbose_print((char *) "FW ECID = ", swh_v2->ecid, sizeof(swh_v2->ecid));
        }

        memset(swh_v2->reserved2,0, sizeof(swh_v2->reserved2));

		// Calculate the payload hash.
		p = sha3_512(infile, payload_st.st_size, md);
		if (!p)
			die(EX_SOFTWARE, "%s", "Cannot get SHA3-512");
		memcpy(swh_v2->payload_hash, md, sizeof(sha2_hash_t));
		verbose_print((char *) "Payload hash = ", md, sizeof(md));

		// Dump the Software header.
		if (params.swhdrfn)
			writeHdr((void *) swh_v2, params.swhdrfn, SOFTWARE_HDR, params.container_version);

		ssig_v2 = (ROM_sw_sig_v2_raw*)&c_v2->sw_data;
		memset(ssig_v2->sw_sig_p, 0, sizeof(ecc_signature_t));
		memset(ssig_v2->sw_sig_s, 0, sizeof(dilithium_signature_t));

		// Write the HW signatures.
		if (params.sw_sigfn_p) {
			getSigRaw(&sigraw, params.sw_sigfn_p);
			verbose_print((char *) "signature P = ", sigraw, sizeof(sigraw));
			memcpy(ssig_v2->sw_sig_p, sigraw, sizeof(ecc_key_t));
		}
		if (params.sw_sigfn_s) {
			size_t sLen = sizeof(ssig_v2->sw_sig_s);
			int r = readBinaryFile(ssig_v2->sw_sig_s, &sLen,params.sw_sigfn_s);
			if (0 != r || sLen != DILITHIUM_SIG_LENGTH)
				die(EX_SOFTWARE, "Failure reading SW SIG S : %s",params.sw_sigfn_s);
			verbose_print((char *) "signature S = ", ssig_v2->sw_sig_s, sizeof(ssig_v2->sw_sig_s));
		}

		// Dump the full container header.
		if (params.cthdrfn)
			writeHdr((void *) c, params.cthdrfn, CONTAINER_HDR, params.container_version);

		// Print container stats.
		size = (uint8_t*) ph_v2 - (uint8_t *) c_v2;
		offset = 0;
		verbose_msg("HW header size        = %4u (%#06x) at offset %4u (%#06x)",
			    size, size, offset, offset);
		size = (uint8_t*) pd_v2 - (uint8_t *) ph_v2;
		offset = (uint8_t*) ph_v2 - (uint8_t *) c_v2;
		verbose_msg("Prefix header size    = %4u (%#06x) at offset %4u (%#06x)",
			    size, size, offset, offset);
		size = (uint8_t*) swh_v2 - (uint8_t *) pd_v2;
		offset = (uint8_t*) pd_v2 - (uint8_t *) c_v2;
		verbose_msg("Prefix data size      = %4u (%#06x) at offset %4u (%#06x)",
			    size, size, offset, offset);
		size = (uint8_t*) ssig_v2 - (uint8_t *) swh_v2;
		offset = (uint8_t*) swh_v2 - (uint8_t *) c_v2;
		verbose_msg("SW header size        = %4u (%#06x) at offset %4u (%#06x)",
			    size, size, offset, offset);

		verbose_msg("TOTAL HEADER SIZE     = %4d (%#0x)", SECURE_BOOT_HEADERS_V2_SIZE,
			    SECURE_BOOT_HEADERS_V2_SIZE);
		verbose_msg("PAYLOAD SIZE          = %4lu (%#0lx)",
			    be64_to_cpu(swh_v2->payload_size), be64_to_cpu(swh_v2->payload_size));
		verbose_msg("TOTAL CONTAINER SIZE  = %4lu (%#0lx)",
			    be64_to_cpu(c_v2->container_size), be64_to_cpu(c_v2->container_size));

		// Write container.
		if ((r = write(fdout, container, SECURE_BOOT_HEADERS_V2_SIZE)) != SECURE_BOOT_HEADERS_V2_SIZE)
			die(EX_SOFTWARE, "Cannot write container header (r = %d) (%s)", r,
			    strerror(errno));

	} else {
		// VERSION 3 CONTAINER

		c_v3->magic_number = cpu_to_be32(ROM_MAGIC_NUMBER);
		c_v3->version = cpu_to_be16(3);
		c_v3->container_size = cpu_to_be64(SECURE_BOOT_HEADERS_V3_SIZE + payload_st.st_size);
		memset(c_v3->hw_pkey_a, 0, sizeof(ecc_key_t));
		memset(c_v3->hw_pkey_d, 0, sizeof(mldsa_key_t));
		if (params.hw_keyfn_a) {
			getPublicKeyRaw(&pubkeyraw, params.hw_keyfn_a);
			verbose_print((char *) "pubkey A = ", pubkeyraw, sizeof(pubkeyraw));
			memcpy(c_v3->hw_pkey_a, pubkeyraw, sizeof(ecc_key_t));
		}
		if (params.hw_keyfn_d) {
			size_t sLen = sizeof(c_v3->hw_pkey_d);
			int r = readBinaryFile(c_v3->hw_pkey_d, &sLen,params.hw_keyfn_d);
			if (0 != r || sLen != MLDSA_87_PUB_KEY_LENGTH)
				die(EX_SOFTWARE, "Failure reading HW PUBKEY D : %s",params.hw_keyfn_d);
			verbose_print((char *) "pubkey D = ", c_v3->hw_pkey_d, sizeof(c_v3->hw_pkey_d));
		}
		p = sha3_512(c_v3->hw_pkey_a, sizeof(ecc_key_t) + sizeof(mldsa_key_t), md);
		if (!p)
			die(EX_SOFTWARE, "%s", "Cannot get SHA3-512");
		verbose_print((char *) "HW keys hash = ", md, sizeof(md));

		ph_v3 = (ROM_prefix_header_v3_raw*)&(c_v3->prefix);
		ph_v3->ver_alg.version = cpu_to_be16(3);
		ph_v3->ver_alg.hash_alg = 2;
		ph_v3->ver_alg.sig_alg = 3;
		ph_v3->reserved = 0;

		// Set flags.
		if (params.hw_flags) {
			if (!isValidHex(params.hw_flags, 4))
				die(EX_DATAERR, "%s",
				    "Invalid input for hw-flags, expecting a 4 byte hexadecimal value");
			uint32_t data;
			sscanf(params.hw_flags, "%x", &data);
			ph_v3->flags = cpu_to_be32(data);
			verbose_msg("hw-flags = %#010x", data);
		} else {
			ph_v3->flags = cpu_to_be32(0x80000000);
		}
		memset(ph_v3->payload_hash, 0, sizeof(sha2_hash_t));
		memset(ph_v3->ecid, 0, ECID_SIZE);
		memset(ph_v3->reserved2, 0, sizeof(ph_v3->reserved2));

		pd_v3 = (ROM_prefix_data_v3_raw*)&c_v3->prefix_data;
		memset(pd_v3->hw_sig_a, 0, sizeof(ecc_signature_t));
		memset(pd_v3->hw_sig_d, 0, sizeof(mldsa_signature_t));

		// Write the HW signatures.
		if (params.hw_sigfn_a) {
			getSigRaw(&sigraw, params.hw_sigfn_a);
			verbose_print((char *) "signature A = ", sigraw, sizeof(sigraw));
			memcpy(pd_v3->hw_sig_a, sigraw, sizeof(ecc_key_t));
		}
		if (params.hw_sigfn_d) {
			size_t sLen = sizeof(pd_v3->hw_sig_d);
			int r = readBinaryFile(pd_v3->hw_sig_d, &sLen,params.hw_sigfn_d);
			if (0 != r || sLen != MLDSA_87_SIG_LENGTH)
				die(EX_SOFTWARE, "Failure reading HW SIG D : %s",params.hw_sigfn_d);
			verbose_print((char *) "signature D = ", pd_v3->hw_sig_d, sizeof(pd_v3->hw_sig_d));
		}
		memset(pd_v3->sw_pkey_p, 0, sizeof(ecc_key_t));
		memset(pd_v3->sw_pkey_s, 0, sizeof(mldsa_key_t));

		// Write the FW keys.
		if (params.sw_keyfn_p) {
			getPublicKeyRaw(&pubkeyraw, params.sw_keyfn_p);
			verbose_print((char *) "pubkey P = ", pubkeyraw, sizeof(pubkeyraw));
			memcpy(pd_v3->sw_pkey_p, pubkeyraw, sizeof(ecc_key_t));
			ph_v3->sw_key_count++;
			ph_v3->payload_size += sizeof(ecc_key_t);
		}
		if (params.sw_keyfn_s) {
			size_t sLen = sizeof(pd_v3->sw_pkey_s);
			int r = readBinaryFile(pd_v3->sw_pkey_s, &sLen,params.sw_keyfn_s);
			if (0 != r || sLen != MLDSA_87_PUB_KEY_LENGTH)
				die(EX_SOFTWARE, "Failure reading SW PUBKEY S : %s",params.sw_keyfn_s);
			verbose_print((char *) "pubkey S = ", pd_v3->sw_pkey_s, sizeof(pd_v3->sw_pkey_s));
			ph_v3->sw_key_count++;
			ph_v3->payload_size += sizeof(mldsa_key_t);
		}
		ph_v3->payload_size = cpu_to_be64(ph_v3->payload_size);
		debug_msg("sw_key_count = %u", ph_v3->sw_key_count);

		// Calculate the SW keys hash.
		p = sha3_512(pd_v3->sw_pkey_p, be64_to_cpu(ph_v3->payload_size), md);
		if (!p)
			die(EX_SOFTWARE, "%s", "Cannot get SHA3-512");
		memcpy(ph_v3->payload_hash, md, sizeof(sha2_hash_t));
		verbose_print((char *) "SW keys hash = ", md, sizeof(md));

		// Dump the Prefix header.
		if (params.prhdrfn)
			writeHdr((void *) ph_v3, params.prhdrfn, PREFIX_HDR, params.container_version);

		swh_v3 = (ROM_sw_header_v3_raw*) &c_v3->swheader;
		swh_v3->ver_alg.version = cpu_to_be16(3);
		swh_v3->ver_alg.hash_alg = 2;
		swh_v3->ver_alg.sig_alg = 3;
		swh_v3->reserved = 0;

		// Add component ID (label).
		if (params.label) {
			if (!isValidAscii(params.label, 0))
				die(EX_DATAERR, "%s",
				    "Invalid input for label, expecting a 8 char ASCII value");
			strncpy((char *) &swh_v3->component_id, params.label, 8);
			verbose_msg("component ID = %.8s",
				    (char * ) &swh_v3->component_id);
		} else {
			swh_v3->component_id = 0;
		}

		// Set flags.
		if (params.sw_flags) {
			if (!isValidHex(params.sw_flags, 4))
				die(EX_DATAERR, "%s",
				    "Invalid input for sw-flags, expecting a 4 byte hexadecimal value");
			uint32_t data;
			sscanf(params.sw_flags, "%x", &data);
			swh_v3->flags = cpu_to_be32(data);
			verbose_msg("sw-flags = %#010x", data);
		} else {
			swh_v3->flags = cpu_to_be32(0x00000000);
		}
		swh_v3->security_version = params.security_version;
		swh_v3->payload_size = cpu_to_be64(payload_st.st_size);
		swh_v3->unprotected_payload_size = 0;

		// Set the FW ECID if provided
		memset(swh_v3->ecid, 0, ECID_SIZE);
		if (params.fw_ecid) {
			if (!isValidHex(params.fw_ecid, ECID_SIZE))
				die(EX_DATAERR, "%s",
				    "Invalid input for sw-ecid, expecting a 16 byte hexadecimal value");
			for (int x = 0; x < ECID_SIZE; x++) {
				sscanf(&(params.fw_ecid[x*2]), "%2hhx", &(swh_v3->ecid[x]));
			}
			verbose_print((char *) "FW ECID = ", swh_v3->ecid, sizeof(swh_v3->ecid));
		}

		memset(swh_v3->reserved2,0, sizeof(swh_v3->reserved2));

		// Calculate the payload hash.
		p = sha3_512(infile, payload_st.st_size, md);
		if (!p)
			die(EX_SOFTWARE, "%s", "Cannot get SHA3-512");
		memcpy(swh_v3->payload_hash, md, sizeof(sha2_hash_t));
		verbose_print((char *) "Payload hash = ", md, sizeof(md));

		// Dump the Software header.
		if (params.swhdrfn)
			writeHdr((void *) swh_v3, params.swhdrfn, SOFTWARE_HDR, params.container_version);

		ssig_v3 = (ROM_sw_sig_v3_raw*)&c_v3->sw_data;
		memset(ssig_v3->sw_sig_p, 0, sizeof(ecc_signature_t));
		memset(ssig_v3->sw_sig_s, 0, sizeof(mldsa_signature_t));

		// Write the HW signatures.
		if (params.sw_sigfn_p) {
			getSigRaw(&sigraw, params.sw_sigfn_p);
			verbose_print((char *) "signature P = ", sigraw, sizeof(sigraw));
			memcpy(ssig_v3->sw_sig_p, sigraw, sizeof(ecc_key_t));
		}
		if (params.sw_sigfn_s) {
			size_t sLen = sizeof(ssig_v3->sw_sig_s);
			int r = readBinaryFile(ssig_v3->sw_sig_s, &sLen,params.sw_sigfn_s);
			if (0 != r || sLen != MLDSA_87_SIG_LENGTH)
				die(EX_SOFTWARE, "Failure reading SW SIG S : %s",params.sw_sigfn_s);
			verbose_print((char *) "signature S = ", ssig_v3->sw_sig_s, sizeof(ssig_v3->sw_sig_s));
		}

		// Dump the full container header.
		if (params.cthdrfn)
			writeHdr((void *) c, params.cthdrfn, CONTAINER_HDR, params.container_version);

		// Print container stats.
		size = (uint8_t*) ph_v3 - (uint8_t *) c_v3;
		offset = 0;
		verbose_msg("HW header size        = %4u (%#06x) at offset %4u (%#06x)",
			    size, size, offset, offset);
		size = (uint8_t*) pd_v3 - (uint8_t *) ph_v3;
		offset = (uint8_t*) ph_v3 - (uint8_t *) c_v3;
		verbose_msg("Prefix header size    = %4u (%#06x) at offset %4u (%#06x)",
			    size, size, offset, offset);
		size = (uint8_t*) swh_v3 - (uint8_t *) pd_v3;
		offset = (uint8_t*) pd_v3 - (uint8_t *) c_v3;
		verbose_msg("Prefix data size      = %4u (%#06x) at offset %4u (%#06x)",
			    size, size, offset, offset);
		size = (uint8_t*) ssig_v3 - (uint8_t *) swh_v3;
		offset = (uint8_t*) swh_v3 - (uint8_t *) c_v3;
		verbose_msg("SW header size        = %4u (%#06x) at offset %4u (%#06x)",
			    size, size, offset, offset);

		verbose_msg("TOTAL HEADER SIZE     = %4d (%#0x)", SECURE_BOOT_HEADERS_V3_SIZE,
			    SECURE_BOOT_HEADERS_V3_SIZE);
		verbose_msg("PAYLOAD SIZE          = %4lu (%#0lx)",
			    be64_to_cpu(swh_v3->payload_size), be64_to_cpu(swh_v3->payload_size));
		verbose_msg("TOTAL CONTAINER SIZE  = %4lu (%#0lx)",
			    be64_to_cpu(c_v3->container_size), be64_to_cpu(c_v3->container_size));

		// Write container.
		if ((r = write(fdout, container, SECURE_BOOT_HEADERS_V3_SIZE)) != SECURE_BOOT_HEADERS_V3_SIZE)
			die(EX_SOFTWARE, "Cannot write container header (r = %d) (%s)", r,
			    strerror(errno));

	}

	if (infile) {
		if ((r = write(fdout, infile, payload_st.st_size))
				!= payload_st.st_size)
			die(EX_SOFTWARE, "Cannot write container payload (r = %d) (%s)", r,
					strerror(errno));
	}
	close(fdout);
	free(container);
	free(buf);
	return 0;
}
