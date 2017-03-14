/* Copyright 2013-2017 IBM Corp.
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

#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <endian.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "ccan/short_types/short_types.h"
#include "libstb/container.h"

#include <stdbool.h>
#include "libstb/container.h"


static void write_header(char *payload,
			 unsigned char *hw_key[], int hw_key_count,
			 unsigned char *sw_key[], int sw_key_count,
			 char *output)
{
	int fdin, fdout;
	void *container = malloc(SECURE_BOOT_HEADERS_SIZE);
	struct stat s;
	char *buf = malloc(4096);
	off_t l;
	void *infile;
	int r;
	ROM_container_raw *c = (ROM_container_raw*)container;
	ROM_prefix_header_raw *ph;
	ROM_prefix_data_raw *pd;
	ROM_sw_header_raw *swh;
	EVP_MD_CTX *mdctx;
	size_t sz;

	memset(container, 0, SECURE_BOOT_HEADERS_SIZE);

	fdin = open(payload, O_RDONLY);
	assert(fdin > 0);
	r = fstat(fdin, &s);
	assert(r==0);
	infile = mmap(NULL, s.st_size, PROT_READ, 0, fdin, 0);
	assert(infile);
	fdout = open(output, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	assert(fdout > 0);

	c->magic_number = cpu_to_be32(ROM_MAGIC_NUMBER);
	c->version = 1;
	c->container_size = cpu_to_be64(SECURE_BOOT_HEADERS_SIZE + s.st_size);
	c->target_hrmor = 0;
	c->stack_pointer = 0;

	if (hw_key_count > 0)
		memcpy(c->hw_pkey_a, hw_key[0], sizeof(ecc_key_t));
	else
		memset(c->hw_pkey_a, 0, sizeof(ecc_key_t));

	if (hw_key_count > 1)
		memcpy(c->hw_pkey_b, hw_key[1], sizeof(ecc_key_t));
	else
		memset(c->hw_pkey_b, 0, sizeof(ecc_key_t));
	if (hw_key_count > 1)
		memcpy(c->hw_pkey_c, hw_key[2], sizeof(ecc_key_t));
	else
		memset(c->hw_pkey_c, 0, sizeof(ecc_key_t));

	ph = container + sizeof(ROM_container_raw);
	ph->ver_alg.version = cpu_to_be16(1);
	ph->ver_alg.hash_alg = 1;
	ph->ver_alg.sig_alg = 1;
	ph->code_start_offset = 0;
	ph->reserved = 0;
	ph->flags = 0;
	ph->sw_key_count = sw_key_count; // Must be >=1, because Hostboot
	memset(ph->payload_hash, 0, sizeof(sha2_hash_t)); // TODO

	ph->ecid_count = 0;

	pd = (ROM_prefix_data_raw*)ph->ecid;
	memset(pd->hw_sig_a, 0, sizeof(ecc_signature_t));
	memset(pd->hw_sig_b, 0, sizeof(ecc_signature_t));
	memset(pd->hw_sig_c, 0, sizeof(ecc_signature_t));
	if (sw_key_count > 0)
		memcpy(pd->sw_pkey_p, sw_key[0], sizeof(ecc_key_t));
	else
		memset(pd->sw_pkey_p, 0, sizeof(ecc_key_t));
	if (sw_key_count > 1)
		memcpy(pd->sw_pkey_q, sw_key[1], sizeof(ecc_key_t));
	else
		memset(pd->sw_pkey_q, 0, sizeof(ecc_key_t));
	if (sw_key_count > 2)
		memcpy(pd->sw_pkey_r, sw_key[2], sizeof(ecc_key_t));
	else
		memset(pd->sw_pkey_r, 0, sizeof(ecc_key_t));

	// FIXME: Compute ph payload hash!
	// FIXME: Store hw signatures

	ph->payload_size = cpu_to_be64(sizeof(ecc_signature_t)*3 + ph->sw_key_count * sizeof(ecc_key_t));

	swh = (ROM_sw_header_raw*)(((void*)pd) + be64_to_cpu(ph->payload_size));
	swh->ver_alg.version = cpu_to_be16(1);
	swh->ver_alg.hash_alg = 1;
	swh->ver_alg.sig_alg = 1;
	swh->code_start_offset = 0;
	swh->reserved = 0;
	swh->flags = 0;
	swh->reserved_0 = 0;
	swh->payload_size = cpu_to_be64(s.st_size);

	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL);
	sz = read(fdin, buf, s.st_size%4096);
	EVP_DigestUpdate(mdctx, buf, sz);
	l = s.st_size - s.st_size%4096;
	while (l) {
		sz = read(fdin, buf, 4096);
		EVP_DigestUpdate(mdctx, buf, sz);
		l-=4096;
	};
	lseek(fdin, 0, SEEK_SET);
	EVP_DigestFinal_ex(mdctx, swh->payload_hash, &sz);
	assert(sz == SHA512_DIGEST_LENGTH);
	EVP_MD_CTX_destroy(mdctx);

	// FIXME: Write software signatures

	r = write(fdout, container, SECURE_BOOT_HEADERS_SIZE);
	assert(r == 4096);
	read(fdin, buf, s.st_size%4096);
	write(fdout, buf, s.st_size%4096);
	l = s.st_size - s.st_size%4096;
	while (l) {
		read(fdin, buf, 4096);
		write(fdout, buf, 4096);
		l-=4096;
	};
	close(fdin);
	close(fdout);

	free(container);
	free(buf);
}

static void usage(char *argv0)
{
	fprintf(stderr, "%s Usage:\n"
		"\n"
		"\t%s  --software-public-key1 sw-key1-public.pem \\\n"
		"\t\t--software-public-key2 sw-key2-public.pem \\\n"
		"\t\t--software-public-key3 sw-key3-public.pem \\\n"
		"\t\t--software-signature1 PAYLOAD.sw-key1-signature \\\n"
		"\t\t--software-signature2 PAYLOAD.sw-key2-signature \\\n"
		"\t\t--software-signature3 PAYLOAD.sw-key3-signature \\\n"
		"\t\t--hardware-public-key1 hw-key1-public.pem \\\n"
		"\t\t--hardware-public-key2 hw-key2-public.pem \\\n"
		"\t\t--hardware-public-key3 hw-key3-public.pem \\\n"
		"\t\t--hardware-signature1 PAYLOAD.hw-key1-signature \\\n"
		"\t\t--hardware-signature2 PAYLOAD.hw-key2-signature \\\n"
		"\t\t--hardware-signature3 PAYLOAD.hw-key3-signature \\\n"
		"\t\tPAYLOAD PAYLOAD.stb\n"
		"\n"
		"This utility creates an OpenPOWER Secure and Trusted Boot "
		"container. You first need to have created a software "
		"header using create-software-container and have signed it "
		"with the hardware keys.\n\n", argv0, argv0);
}

static int read_key(char *file, unsigned char** buf, size_t *bufsz)
{
	FILE *pkfp;
	EVP_PKEY* pkey;
	EC_KEY* key;
	const EC_GROUP *ecgrp;
	const EC_POINT *ecpoint;
	char ebuf[256];

	pkfp = fopen(file, "r");
	if (!pkfp) {
		fprintf(stderr, "Unable to open public key (%s): %s\n",
			file, strerror(errno));
		return -1;
	}

	pkey = PEM_read_PUBKEY(pkfp, NULL, NULL, NULL);
	if (!pkey) {
		ERR_error_string_n(ERR_get_error(), ebuf, sizeof(ebuf));
		fprintf(stderr, "Unable to parse PEM of software public key (%s): %s\n",
			file, ebuf);
		return -2;
	}

	key = EVP_PKEY_get1_EC_KEY(pkey);
	if (!key) {
		ERR_error_string_n(ERR_get_error(), ebuf, sizeof(ebuf));
		fprintf(stderr, "Unable to extract EC key (%s): %s\n",
			file, ebuf);
		return -3;
	}

	ecgrp = EC_KEY_get0_group(key);
	if (!ecgrp) {
		ERR_error_string_n(ERR_get_error(), ebuf, sizeof(ebuf));
		fprintf(stderr, "Unable to extract EC group (%s): %s\n",
			file, ebuf);
		return -4;
	}

	ecpoint = EC_KEY_get0_public_key(key);
	if (!ecpoint) {
		ERR_error_string_n(ERR_get_error(), ebuf, sizeof(ebuf));
		fprintf(stderr, "Unable to extract EC public key (%s): %s\n",
			file, ebuf);
		return -5;
	}

	*bufsz = EC_POINT_point2oct(ecgrp, ecpoint,
				    POINT_CONVERSION_UNCOMPRESSED,
				    NULL, 0, NULL);
	if (*bufsz == 0) {
		fprintf(stderr, "Invalid buffer size for EC_POINT_point2oct\n");
		return -6;
	}
	*buf = malloc(*bufsz);
	if (*buf == NULL) {
		fprintf(stderr, "ENOMEM\n");
		return -7;
	}
	*bufsz  = EC_POINT_point2oct(ecgrp, ecpoint,
				     POINT_CONVERSION_UNCOMPRESSED,
				     *buf,
				     *bufsz,
				     NULL);
	if (*bufsz == 0) {
		free(*buf);
		ERR_error_string_n(ERR_get_error(), ebuf, sizeof(ebuf));
		fprintf(stderr, "SSL error: %s\n", ebuf);
		return -8;
	}

	return 0;
}

int main(int argc, char* argv[])
{
	int c;
	int digit_optind = 0;
	int r;
	char* payload;
	char* output;
	char* software_public_key[3] = { NULL, NULL, NULL };
	char* software_signature[3] = { NULL, NULL, NULL };
	char* hardware_public_key[3] = { NULL, NULL, NULL };
	char* hardware_signature[3] = { NULL, NULL, NULL };
	unsigned char* sw_keys[3] = { NULL, NULL, NULL };
	size_t sw_keysz[3];
	unsigned char* hw_keys[3] = { NULL, NULL, NULL };
	size_t hw_keysz[3];

	while(1) {
		int this_option_optind = optind ? optind : 1;
		int option_index = 0;
		static struct option long_options[] = {
			{"software-public-key1", required_argument, 0, 0 },
			{"software-public-key2", required_argument, 0, 0 },
			{"software-public-key3", required_argument, 0, 0 },
			{"software-signature1",  required_argument, 0, 0 },
			{"software-signature2",  required_argument, 0, 0 },
			{"software-signature3",  required_argument, 0, 0 },
			{"hardware-public-key1", required_argument, 0, 0 },
			{"hardware-public-key2", required_argument, 0, 0 },
			{"hardware-public-key3", required_argument, 0, 0 },
			{"hardware-signature1",  required_argument, 0, 0 },
			{"hardware-signature2",  required_argument, 0, 0 },
			{"hardware-signature3",  required_argument, 0, 0 },
		};

		c = getopt_long(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;

		switch(c) {
		case 0:
			if (!optarg) {
				fprintf(stderr, "Parameter %s requires argument\n", long_options[option_index].name);
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			switch (option_index) {
			case 0:
			case 1:
			case 2:
				software_public_key[option_index] = optarg;
				break;
			case 3:
			case 4:
			case 5:
				software_signature[option_index-3] = optarg;
				break;
			case 6:
			case 7:
			case 8:
				hardware_public_key[option_index-6] = optarg;
				break;
			case 9:
			case 10:
			case 11:
				hardware_signature[option_index-9] = optarg;
				break;

			default:
				assert(false);
			}
			break;
		default:
			assert(false);
		}

	};

	if (optind + 2 != argc) {
		fprintf(stderr, "Too many/few parameters\n");
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	payload = argv[optind];
	output = argv[optind+1];

	r = read_key(software_public_key[0], &sw_keys[0], &sw_keysz[0]);
	if (r)
		exit(r);
	r = read_key(software_public_key[1], &sw_keys[1], &sw_keysz[1]);
	if (r)
		exit(r);
	r = read_key(software_public_key[2], &sw_keys[2], &sw_keysz[2]);
	if (r)
		exit(r);

	r = read_key(hardware_public_key[0], &hw_keys[0], &hw_keysz[0]);
	if (r)
		exit(r);
	r = read_key(hardware_public_key[1], &hw_keys[1], &hw_keysz[1]);
	if (r)
		exit(r);
	r = read_key(hardware_public_key[2], &hw_keys[2], &hw_keysz[2]);
	if (r)
		exit(r);

	write_header(payload, hw_keys, 3, sw_keys, 3, output);

	return 0;
}
