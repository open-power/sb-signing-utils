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

/*
 * create-software-container
 * *************************
 *
 * creates the bit of the STB container that needs to be signed by the
 * hardware keys
 */

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

static void usage(char *argv0)
{
	fprintf(stderr, "%s Usage:\n"
		"\n"
		"\t%s --software-signature1 PAYLOAD.sw-key1-signature \\\n"
		"\t\t--software-signature2 PAYLOAD.sw-key2-signature \\\n"
		"\t\t--software-signature3 PAYLOAD.sw-key3-signature \\\n"
		"\t\tPAYLOAD PAYLOAD.software-container\n"
		"\n"
		"This utility creates a software container, which then "
		"needs to be signed by hardware keys before the final "
		"secure and trusted boot container can be created for "
		"OpenPOWER firmware.\n\n", argv0, argv0);
}

static int create_software_container(char* software_signature_files[],
				     char *payload,
				     char *output)
{
	int fdin, fdout;
	int r;
	struct stat s;
	off_t l;
	char buf[4096];
	char container[4096];
	size_t containersz = sizeof(ROM_sw_header_raw) + sizeof(ROM_sw_sig_raw);
	size_t sz;
	EVP_MD_CTX *mdctx;
	ROM_sw_header_raw *swh = container;
	ROM_sw_sig_raw *swsig = container + sizeof(ROM_sw_header_raw);

	memset(buf, 0, sizeof(buf));

	fdin = open(payload, O_RDONLY);
	assert(fdin > 0);
	r = fstat(fdin, &s);
	assert(r==0);
	fdout = open(output, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	assert(fdout > 0);

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

	r = write(fdout, container, containersz);
	assert(r == containersz);

	close(fdin);
	return 0;
}

int main(int argc, char *argv[])
{
	int c;
	int digit_optind = 0;
	char* software_signature[3] = { NULL, NULL, NULL };

	char* payload;
	char* output;

	while(1) {
		int this_option_optind = optind ? optind : 1;
		int option_index = 0;
		static struct option long_options[] = {
			{"software-signature1",  required_argument, 0, 0 },
			{"software-signature2",  required_argument, 0, 0 },
			{"software-signature3",  required_argument, 0, 0 },
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
				software_signature[option_index] = optarg;
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

	return create_software_container(software_signature,
					 payload,
					 output);
}
