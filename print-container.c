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

#include <alloca.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/opensslv.h>
#include <openssl/ossl_typ.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stddef.h>
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

#ifdef ADD_DILITHIUM
#include "mlca2.h"
#endif

char *progname;

bool print_stats;
bool verbose, debug;
int wrap = 100;

ecc_key_t ECDSA_KEY_NULL;

typedef struct keyprops {
	char index;
	char *name;
	const ecc_key_t *key;
	const ecc_signature_t *sig;
} Keyprops;

static struct {
	char *imagefn;
	bool validate;
	bool ignore_remainder;
	char *verify;
	bool print_container;
} params;

static void usage(int status);

static bool getPayloadHash(int fdin, uint64_t pl_sz_expected, unsigned char *md, int container_version);
static bool getVerificationHash(char *input, unsigned char *md, int len);
static bool verify_signature(const char *moniker, const unsigned char *dgst,
		int dgst_len, const ecc_signature_t sig_raw, const ecc_key_t key_raw);
static bool verify_dilithium_signature(const char *moniker, const unsigned char *dgst,
				       int dgst_len, const dilithium_signature_t sig_raw, const dilithium_key_t key_raw);
static bool verify_mldsa_87_signature(const char *moniker, const unsigned char *dgst,
				       int dgst_len, const mldsa_signature_t sig_raw, const mldsa_key_t key_raw);


unsigned char *calc_hash(uint8_t hash_alg,
			 const unsigned char *data, size_t len,
			 unsigned char *md)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	uint32_t md_len = SHA512_DIGEST_LENGTH;
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	const EVP_MD* alg;

	switch (hash_alg) {
	case HASH_ALG_SHA3_512:
		alg = EVP_sha3_512();
		break;
	default:
		return NULL;
	}
	EVP_DigestInit_ex(ctx, alg, NULL);
	EVP_DigestUpdate(ctx, data, len);
	EVP_DigestFinal_ex(ctx, md, &md_len);
	EVP_MD_CTX_destroy(ctx);
	return md;
#else
	return NULL;
#endif
}

static void print_bytes(char *lead, uint8_t *buffer, size_t buflen)
{
	unsigned int i;
	unsigned int width;
	unsigned int leadbytes = strlen(lead);
	leadbytes = leadbytes > 30 ? 30 : leadbytes;
	width = (wrap - leadbytes) / 2;
	width = (width < 1) ? INT_MAX : width;

	fprintf(stdout, "%s", lead);
	for (i = 1; i < buflen + 1; i++) {
		fprintf(stdout, "%02x", buffer[i - 1]);
		if (((i % width) == 0) && (i < buflen))
			fprintf(stdout, "\n%*c", leadbytes, ' ');
	}
	fprintf(stdout, "\n");
}

bool stb_is_container(const void *buf, size_t size)
{
	ROM_container_raw *c;

	c = (ROM_container_raw*) buf;
	if (!buf || size < SECURE_BOOT_HEADERS_SIZE)
		return false;
	if (be32_to_cpu(c->magic_number) != ROM_MAGIC_NUMBER)
		return false;
	return true;
}

bool stb_is_v2_container(const void *buf, size_t size)
{
	ROM_container_v2_raw *c;

	c = (ROM_container_v2_raw*) buf;
	if (!buf || size < SECURE_BOOT_HEADERS_V2_SIZE)
		return false;
	if (be32_to_cpu(c->magic_number) != ROM_MAGIC_NUMBER)
		return false;
	if (be16_to_cpu(c->version) != 2) {
		return false;
	}
	return true;
}

bool stb_is_v3_container(const void *buf, size_t size)
{
	ROM_container_v3_raw *c;

	c = (ROM_container_v3_raw*) buf;
	if (!buf || size < SECURE_BOOT_HEADERS_V3_SIZE)
		return false;
	if (be32_to_cpu(c->magic_number) != ROM_MAGIC_NUMBER)
		return false;
	if (be16_to_cpu(c->version) != 3) {
		return false;
	}
	return true;
}

int parse_stb_container(const void* data, size_t len,
		struct parsed_stb_container *c)
{
	const size_t prefix_data_min_size = 3 * (EC_COORDBYTES * 2);
	c->buf = data;
	c->bufsz = len;
	c->c = data;
	c->ph = data += sizeof(ROM_container_raw);
	c->pd = data += sizeof(ROM_prefix_header_raw)
			+ (c->ph->ecid_count * ECID_SIZE);
	c->sh = data += prefix_data_min_size
			+ c->ph->sw_key_count * (EC_COORDBYTES * 2);
	c->ssig = data += sizeof(ROM_sw_header_raw) + c->sh->ecid_count * ECID_SIZE;

	return 0;
}

int parse_stb_container_v2(const void* data, size_t len,
                           struct parsed_stb_container_v2 *c)
{
	c->buf = data;
	c->bufsz = len;
	c->c = data;
	c->ph = &(c->c->prefix);
	c->pd = &(c->c->prefix_data);
	c->sh = &(c->c->swheader);
	c->ssig = &(c->c->sw_data);

	return 0;
}

int parse_stb_container_v3(const void* data, size_t len,
                           struct parsed_stb_container_v3 *c)
{
	c->buf = data;
	c->bufsz = len;
	c->c = data;
	c->ph = &(c->c->prefix);
	c->pd = &(c->c->prefix_data);
	c->sh = &(c->c->swheader);
	c->ssig = &(c->c->sw_data);

	return 0;
}

static void display_version_raw(const ROM_version_raw v)
{
	printf("ver_alg:\n");
	printf("  version:  %04x\n", be16_to_cpu(v.version));
	if (v.hash_alg == HASH_ALG_SHA512) printf("  hash_alg: %02x (%s)\n", v.hash_alg, "SHA512");
	else if (v.hash_alg == HASH_ALG_SHA3_512) printf("  hash_alg: %02x (%s)\n", v.hash_alg, "SHA3-512");
	else printf("  hash_alg: %02x (%s)\n", v.hash_alg, "UNKNOWN");
	if (v.sig_alg == SIG_ALG_SHA512_ECDSA)	printf("  sig_alg:  %02x (%s)\n", v.sig_alg, "SHA512/ECDSA-521");
	else if (v.sig_alg == SIG_ALG_SHA3_512_ECDSA_DIL) printf("  sig_alg:  %02x (%s)\n", v.sig_alg, "SHA3-512, ECDSA-521/Dilithium r2 8/7");
	else if (v.sig_alg == SIG_ALG_SHA3_512_ECDSA_MLDSA) printf(" sig_alg:  %02x (%s)\n", v.sig_alg, "SHA3-512, ECDSA 521/ML-DSA-87");
	else printf("  sig_alg:  %02x (%s)\n", v.sig_alg, "UNKNOWN");
}

static void display_container_stats(const struct parsed_stb_container *c)
{
	unsigned int size, offset;

	printf("Container stats:\n");
	size = (uint8_t*) c->ph - (uint8_t *) c->c;
	offset = (uint8_t*) c->c - (uint8_t *) c->buf;
	printf("  HW header size        = %4u (%#06x) at offset %4u (%#06x)\n",
			size, size, offset, offset);
	size = (uint8_t*) c->pd - (uint8_t *) c->ph;
	offset = (uint8_t*) c->ph - (uint8_t *) c->buf;
	printf("  Prefix header size    = %4u (%#06x) at offset %4u (%#06x)\n",
			size, size, offset, offset);
	size = (uint8_t*) c->sh - (uint8_t *) c->pd;
	offset = (uint8_t*) c->pd - (uint8_t *) c->buf;
	printf("  Prefix data size      = %4u (%#06x) at offset %4u (%#06x)\n",
			size, size, offset, offset);
	size = (uint8_t*) c->ssig - (uint8_t *) c->sh;
	offset = (uint8_t*) c->sh - (uint8_t *) c->buf;
	printf("  SW header size        = %4u (%#06x) at offset %4u (%#06x)\n",
			size, size, offset, offset);
	size = sizeof(ecc_key_t) * c->ph->sw_key_count;
	offset = (uint8_t*) c->ssig - (uint8_t *) c->buf;
	printf("  SW signature size     = %4u (%#06x) at offset %4u (%#06x)\n",
			size, size, offset, offset);

	printf("  TOTAL HEADER SIZE     = %4lu (%#0lx)\n", c->bufsz, c->bufsz);
	printf("  PAYLOAD SIZE          = %4lu (%#0lx)\n",
			be64_to_cpu(c->sh->payload_size), be64_to_cpu(c->sh->payload_size));
	printf("  TOTAL CONTAINER SIZE  = %4lu (%#0lx)\n",
			be64_to_cpu(c->c->container_size),
			be64_to_cpu(c->c->container_size));
	printf("\n");
}

static void display_container_stats_v2(const struct parsed_stb_container_v2 *c)
{
	unsigned int size, offset;

	printf("Container stats:\n");
	size = (uint8_t*) c->ph - (uint8_t *) c->c;
	offset = (uint8_t*) c->c - (uint8_t *) c->buf;
	printf("  HW header size        = %4u (%#06x) at offset %4u (%#06x)\n",
			size, size, offset, offset);
	size = (uint8_t*) c->pd - (uint8_t *) c->ph;
	offset = (uint8_t*) c->ph - (uint8_t *) c->buf;
	printf("  Prefix header size    = %4u (%#06x) at offset %4u (%#06x)\n",
			size, size, offset, offset);
	size = (uint8_t*) c->sh - (uint8_t *) c->pd;
	offset = (uint8_t*) c->pd - (uint8_t *) c->buf;
	printf("  Prefix data size      = %4u (%#06x) at offset %4u (%#06x)\n",
			size, size, offset, offset);
	size = (uint8_t*) c->ssig - (uint8_t *) c->sh;
	offset = (uint8_t*) c->sh - (uint8_t *) c->buf;
	printf("  SW header size        = %4u (%#06x) at offset %4u (%#06x)\n",
			size, size, offset, offset);

	printf("  TOTAL HEADER SIZE     = %4lu (%#0lx)\n", c->bufsz, c->bufsz);
	printf("  PAYLOAD SIZE          = %4lu (%#0lx)\n",
			be64_to_cpu(c->sh->payload_size), be64_to_cpu(c->sh->payload_size));
	printf("  TOTAL CONTAINER SIZE  = %4lu (%#0lx)\n",
			be64_to_cpu(c->c->container_size),
			be64_to_cpu(c->c->container_size));
	printf("\n");
}

static void display_container_stats_v3(const struct parsed_stb_container_v3 *c)
{
	unsigned int size, offset;

	printf("Container stats:\n");
	size = (uint8_t*) c->ph - (uint8_t *) c->c;
	offset = (uint8_t*) c->c - (uint8_t *) c->buf;
	printf("  HW header size        = %4u (%#06x) at offset %4u (%#06x)\n",
			size, size, offset, offset);
	size = (uint8_t*) c->pd - (uint8_t *) c->ph;
	offset = (uint8_t*) c->ph - (uint8_t *) c->buf;
	printf("  Prefix header size    = %4u (%#06x) at offset %4u (%#06x)\n",
			size, size, offset, offset);
	size = (uint8_t*) c->sh - (uint8_t *) c->pd;
	offset = (uint8_t*) c->pd - (uint8_t *) c->buf;
	printf("  Prefix data size      = %4u (%#06x) at offset %4u (%#06x)\n",
			size, size, offset, offset);
	size = (uint8_t*) c->ssig - (uint8_t *) c->sh;
	offset = (uint8_t*) c->sh - (uint8_t *) c->buf;
	printf("  SW header size        = %4u (%#06x) at offset %4u (%#06x)\n",
			size, size, offset, offset);

	printf("  TOTAL HEADER SIZE     = %4lu (%#0lx)\n", c->bufsz, c->bufsz);
	printf("  PAYLOAD SIZE          = %4lu (%#0lx)\n",
			be64_to_cpu(c->sh->payload_size), be64_to_cpu(c->sh->payload_size));
	printf("  TOTAL CONTAINER SIZE  = %4lu (%#0lx)\n",
			be64_to_cpu(c->c->container_size),
			be64_to_cpu(c->c->container_size));
	printf("\n");
}

static void display_container(struct parsed_stb_container c)
{
	unsigned char md[SHA512_DIGEST_LENGTH];
	void *p;

	printf("Container:\n");
	printf("magic:          0x%04x\n", be32_to_cpu(c.c->magic_number));
	printf("version:        0x%02x\n", be16_to_cpu(c.c->version));
	printf("container_size: 0x%08lx (%lu)\n", be64_to_cpu(c.c->container_size),
			be64_to_cpu(c.c->container_size));
	printf("target_hrmor:   0x%08lx\n", be64_to_cpu(c.c->target_hrmor));
	printf("stack_pointer:  0x%08lx\n", be64_to_cpu(c.c->stack_pointer));
	print_bytes((char *) "hw_pkey_a: ", (uint8_t *) c.c->hw_pkey_a,
			sizeof(c.c->hw_pkey_a));
	print_bytes((char *) "hw_pkey_b: ", (uint8_t *) c.c->hw_pkey_b,
			sizeof(c.c->hw_pkey_b));
	print_bytes((char *) "hw_pkey_c: ", (uint8_t *) c.c->hw_pkey_c,
			sizeof(c.c->hw_pkey_c));

	p = SHA512(c.c->hw_pkey_a, sizeof(ecc_key_t) * 3, md);
	if (!p)
		die(EX_SOFTWARE, "%s", "Cannot get SHA512");
	printf("HW keys hash (calculated):\n");
	print_bytes((char *) "           ", (uint8_t *) md, sizeof(md));
	printf("\n");

	printf("Prefix Header:\n");
	display_version_raw(c.ph->ver_alg);
	printf("code_start_offset: %08lx\n", be64_to_cpu(c.ph->code_start_offset));
	printf("reserved:          %08lx\n", be64_to_cpu(c.ph->reserved));
	printf("flags:             %08x\n", be32_to_cpu(c.ph->flags));
	printf("sw_key_count:      %02x\n", c.ph->sw_key_count);
	printf("payload_size:      %08lx\n", be64_to_cpu(c.ph->payload_size));
	print_bytes((char *) "payload_hash:      ", (uint8_t *) c.ph->payload_hash,
			sizeof(c.ph->payload_hash));
	printf("ecid_count:        %02x\n", c.ph->ecid_count);

	for (int i = 0; i < c.ph->ecid_count; i++) {
		printf("ecid:              ");
		print_bytes((char *) "ecid:              ",
				(uint8_t *) c.ph->ecid[i].ecid, sizeof(c.ph->ecid[i].ecid));
		printf("\n");
	}
	printf("\n");

	printf("Prefix Data:\n");
	print_bytes((char *) "hw_sig_a:  ", (uint8_t *) c.pd->hw_sig_a, sizeof(c.pd->hw_sig_a));
	print_bytes((char *) "hw_sig_b:  ", (uint8_t *) c.pd->hw_sig_b, sizeof(c.pd->hw_sig_b));
	print_bytes((char *) "hw_sig_c:  ", (uint8_t *) c.pd->hw_sig_c, sizeof(c.pd->hw_sig_c));

	if (c.ph->sw_key_count >=1)
		print_bytes((char *) "sw_pkey_p: ", (uint8_t *) c.pd->sw_pkey_p, sizeof(c.pd->sw_pkey_p));
	if (c.ph->sw_key_count >=2)
		print_bytes((char *) "sw_pkey_q: ", (uint8_t *) c.pd->sw_pkey_q, sizeof(c.pd->sw_pkey_q));
	if (c.ph->sw_key_count >=3)
		print_bytes((char *) "sw_pkey_r: ", (uint8_t *) c.pd->sw_pkey_r, sizeof(c.pd->sw_pkey_r));

	printf("\n");

	printf("Software Header:\n");
	display_version_raw(c.sh->ver_alg);
	printf("code_start_offset: %08lx\n", be64_to_cpu(c.sh->code_start_offset));
	printf("reserved:          %08lx\n", be64_to_cpu(c.sh->reserved));
	printf("reserved (ASCII):  %.8s\n", (char *) &(c.sh->reserved));
	printf("flags:             %08x\n", be32_to_cpu(c.sh->flags));
	printf("security_version:  %02x\n", c.sh->security_version);
	printf("payload_size:      %08lx (%lu)\n", be64_to_cpu(c.sh->payload_size),
			be64_to_cpu(c.sh->payload_size));
	print_bytes((char *) "payload_hash:      ", (uint8_t *) c.sh->payload_hash,
			sizeof(c.sh->payload_hash));
	printf("ecid_count:        %02x\n", c.sh->ecid_count);

	for (int i = 0; i < c.sh->ecid_count; i++) {
		printf("ecid:              ");
		print_bytes((char *) "ecid:              ",
				(uint8_t *) c.sh->ecid[i].ecid, sizeof(c.sh->ecid[i].ecid));
		printf("\n");
	}
	printf("\n");

	printf("Software Signatures:\n");
	print_bytes((char *) "sw_sig_p:  ", (uint8_t *) c.ssig->sw_sig_p,
			sizeof(c.ssig->sw_sig_p));
	print_bytes((char *) "sw_sig_q:  ", (uint8_t *) c.ssig->sw_sig_q,
			sizeof(c.ssig->sw_sig_q));
	print_bytes((char *) "sw_sig_r:  ", (uint8_t *) c.ssig->sw_sig_r,
			sizeof(c.ssig->sw_sig_r));
	printf("\n");

	if (print_stats)
	display_container_stats(&c);
}

static void display_container_v2(struct parsed_stb_container_v2 c)
{
	unsigned char md[SHA512_DIGEST_LENGTH];
	void *p;

	printf("Container:\n");
	printf("magic:          0x%04x\n", be32_to_cpu(c.c->magic_number));
	printf("version:        0x%02x\n", be16_to_cpu(c.c->version));
	printf("container_size: 0x%08lx (%lu)\n", be64_to_cpu(c.c->container_size),
			be64_to_cpu(c.c->container_size));
	print_bytes((char *) "hw_pkey_a: ", (uint8_t *) c.c->hw_pkey_a,
			sizeof(c.c->hw_pkey_a));
	print_bytes((char *) "hw_pkey_d: ", (uint8_t *) c.c->hw_pkey_d,
			sizeof(c.c->hw_pkey_d));

	p = calc_hash(HASH_ALG_SHA3_512, c.c->hw_pkey_a, sizeof(ecc_key_t) + sizeof(dilithium_key_t), md);
	if (!p)
		die(EX_SOFTWARE, "%s", "Cannot get SHA3-512");
	printf("HW keys hash (calculated):\n");
	print_bytes((char *) "           ", (uint8_t *) md, sizeof(md));
	printf("\n");

	printf("Prefix Header:\n");
	display_version_raw(c.ph->ver_alg);
	printf("reserved:          %08lx\n", be64_to_cpu(c.ph->reserved));
	printf("flags:             %08x\n", be32_to_cpu(c.ph->flags));
	printf("sw_key_count:      %02x\n", c.ph->sw_key_count);
	printf("payload_size:      %08lx\n", be64_to_cpu(c.ph->payload_size));
	print_bytes((char *) "payload_hash:      ", (uint8_t *) c.ph->payload_hash,
			sizeof(c.ph->payload_hash));
	print_bytes((char *) "ecid:              ",
		    (uint8_t *) c.ph->ecid, sizeof(c.ph->ecid));
	printf("\n");
	printf("\n");

	printf("Prefix Data:\n");
	print_bytes((char *) "hw_sig_a:  ", (uint8_t *) c.pd->hw_sig_a, sizeof(c.pd->hw_sig_a));
	print_bytes((char *) "hw_sig_d:  ", (uint8_t *) c.pd->hw_sig_d, sizeof(c.pd->hw_sig_d));

	if (c.ph->sw_key_count >=1)
		print_bytes((char *) "sw_pkey_p: ", (uint8_t *) c.pd->sw_pkey_p, sizeof(c.pd->sw_pkey_p));
	if (c.ph->sw_key_count >=2)
		print_bytes((char *) "sw_pkey_s: ", (uint8_t *) c.pd->sw_pkey_s, sizeof(c.pd->sw_pkey_s));
	printf("\n");

	printf("Software Header:\n");
	display_version_raw(c.sh->ver_alg);
	printf("reserved:          %08lx\n", be64_to_cpu(c.sh->reserved));
	printf("component id:      %08lx\n", be64_to_cpu(c.sh->component_id));
	printf("component id (ASCII): %.8s\n", (char *) &(c.sh->component_id));
	printf("flags:             %08x\n", be32_to_cpu(c.sh->flags));
	printf("security_version:  %02x\n", c.sh->security_version);
	printf("payload_size:      %08lx (%lu)\n", be64_to_cpu(c.sh->payload_size),
			be64_to_cpu(c.sh->payload_size));
	printf("unprotected payload_size: %08lx (%lu)\n", be64_to_cpu(c.sh->unprotected_payload_size),
			be64_to_cpu(c.sh->unprotected_payload_size));
	print_bytes((char *) "payload_hash:      ", (uint8_t *) c.sh->payload_hash,
			sizeof(c.sh->payload_hash));
	print_bytes((char *) "ecid:              ",
		    (uint8_t *) c.sh->ecid, sizeof(c.sh->ecid));
	printf("\n");
	printf("\n");

	printf("Software Signatures:\n");
	print_bytes((char *) "sw_sig_p:  ", (uint8_t *) c.ssig->sw_sig_p,
			sizeof(c.ssig->sw_sig_p));
	print_bytes((char *) "sw_sig_s:  ", (uint8_t *) c.ssig->sw_sig_s,
			sizeof(c.ssig->sw_sig_s));
	printf("\n");

	if (print_stats)
        display_container_stats_v2(&c);
}

static void display_container_v3(struct parsed_stb_container_v3 c)
{
	unsigned char md[SHA512_DIGEST_LENGTH];
	void *p;

	printf("Container:\n");
	printf("magic:          0x%04x\n", be32_to_cpu(c.c->magic_number));
	printf("version:        0x%02x\n", be16_to_cpu(c.c->version));
	printf("container_size: 0x%08lx (%lu)\n", be64_to_cpu(c.c->container_size),
			be64_to_cpu(c.c->container_size));
	print_bytes((char *) "hw_pkey_a: ", (uint8_t *) c.c->hw_pkey_a,
			sizeof(c.c->hw_pkey_a));
	print_bytes((char *) "hw_pkey_d: ", (uint8_t *) c.c->hw_pkey_d,
			sizeof(c.c->hw_pkey_d));

	p = calc_hash(HASH_ALG_SHA3_512, c.c->hw_pkey_a, sizeof(ecc_key_t) + sizeof(mldsa_key_t), md);
	if (!p)
		die(EX_SOFTWARE, "%s", "Cannot get SHA3-512");
	printf("HW keys hash (calculated):\n");
	print_bytes((char *) "           ", (uint8_t *) md, sizeof(md));
	printf("\n");

	printf("Prefix Header:\n");
	display_version_raw(c.ph->ver_alg);
	printf("reserved:          %08lx\n", be64_to_cpu(c.ph->reserved));
	printf("flags:             %08x\n", be32_to_cpu(c.ph->flags));
	printf("sw_key_count:      %02x\n", c.ph->sw_key_count);
	printf("payload_size:      %08lx\n", be64_to_cpu(c.ph->payload_size));
	print_bytes((char *) "payload_hash:      ", (uint8_t *) c.ph->payload_hash,
			sizeof(c.ph->payload_hash));
	print_bytes((char *) "ecid:              ",
		    (uint8_t *) c.ph->ecid, sizeof(c.ph->ecid));
	printf("\n");
	printf("\n");

	printf("Prefix Data:\n");
	print_bytes((char *) "hw_sig_a:  ", (uint8_t *) c.pd->hw_sig_a, sizeof(c.pd->hw_sig_a));
	print_bytes((char *) "hw_sig_d:  ", (uint8_t *) c.pd->hw_sig_d, sizeof(c.pd->hw_sig_d));

	if (c.ph->sw_key_count >=1)
		print_bytes((char *) "sw_pkey_p: ", (uint8_t *) c.pd->sw_pkey_p, sizeof(c.pd->sw_pkey_p));
	if (c.ph->sw_key_count >=2)
		print_bytes((char *) "sw_pkey_s: ", (uint8_t *) c.pd->sw_pkey_s, sizeof(c.pd->sw_pkey_s));
	printf("\n");

	printf("Software Header:\n");
	display_version_raw(c.sh->ver_alg);
	printf("reserved:          %08lx\n", be64_to_cpu(c.sh->reserved));
	printf("component id:      %08lx\n", be64_to_cpu(c.sh->component_id));
	printf("component id (ASCII): %.8s\n", (char *) &(c.sh->component_id));
	printf("flags:             %08x\n", be32_to_cpu(c.sh->flags));
	printf("security_version:  %02x\n", c.sh->security_version);
	printf("payload_size:      %08lx (%lu)\n", be64_to_cpu(c.sh->payload_size),
			be64_to_cpu(c.sh->payload_size));
	printf("unprotected payload_size: %08lx (%lu)\n", be64_to_cpu(c.sh->unprotected_payload_size),
			be64_to_cpu(c.sh->unprotected_payload_size));
	print_bytes((char *) "payload_hash:      ", (uint8_t *) c.sh->payload_hash,
			sizeof(c.sh->payload_hash));
	print_bytes((char *) "ecid:              ",
		    (uint8_t *) c.sh->ecid, sizeof(c.sh->ecid));
	printf("\n");
	printf("\n");

	printf("Software Signatures:\n");
	print_bytes((char *) "sw_sig_p:  ", (uint8_t *) c.ssig->sw_sig_p,
			sizeof(c.ssig->sw_sig_p));
	print_bytes((char *) "sw_sig_s:  ", (uint8_t *) c.ssig->sw_sig_s,
			sizeof(c.ssig->sw_sig_s));
	printf("\n");

	if (print_stats)
        display_container_stats_v3(&c);
}

static bool validate_container(struct parsed_stb_container c, int fdin)
{
	static int n;
	static int status = true;

	Keyprops *k;

	Keyprops hwKeylist[] = {
		{ 'a', "HW_key_A", &(c.c->hw_pkey_a), &(c.pd->hw_sig_a) },
		{ 'b', "HW_key_B", &(c.c->hw_pkey_b), &(c.pd->hw_sig_b) },
		{ 'c', "HW_key_C", &(c.c->hw_pkey_c), &(c.pd->hw_sig_c) },
		{ 0, NULL, NULL, NULL },
	};
	Keyprops swKeylist[] = {
		{ 'p', "SW_key_P", &(c.pd->sw_pkey_p), &(c.ssig->sw_sig_p) },
		{ 'q', "SW_key_Q", &(c.pd->sw_pkey_q), &(c.ssig->sw_sig_q) },
		{ 'r', "SW_key_R", &(c.pd->sw_pkey_r), &(c.ssig->sw_sig_r) },
		{ 0, NULL, NULL, NULL },
	};

	void *md = alloca(SHA512_DIGEST_LENGTH);
	void *p;

	// Get Prefix header hash.
	p = SHA512((uint8_t *) c.ph, sizeof(ROM_prefix_header_raw), md);
	if (!p)
		die(EX_SOFTWARE, "%s", "Cannot get SHA512");
	if (verbose) print_bytes((char *) "PR header hash = ", (uint8_t *) md,
			SHA512_DIGEST_LENGTH);

	// Verify HW key sigs.
	for (k = hwKeylist; k->index; k++) {

		if (memcmp(k->key, &ECDSA_KEY_NULL, sizeof(ecc_key_t)))
			status = verify_signature(k->name, md, SHA512_DIGEST_LENGTH,
					*(k->sig), *(k->key)) && status;
		else
			if (verbose) printf("%s is NULL, skipping signature check.\n", k->name);
	}
	if (verbose) printf("\n");

	// Get SW header hash.
	p = SHA512((uint8_t *) c.sh, sizeof(ROM_sw_header_raw), md);
	if (!p)
		die(EX_SOFTWARE, "%s", "Cannot get SHA512");
	if (verbose) print_bytes((char *) "SW header hash = ", (uint8_t *) md,
			SHA512_DIGEST_LENGTH);

	// Verify SW key sigs.
	for (k = swKeylist, n = 1; k->index && n <= c.ph->sw_key_count; k++, n++) {

		if (memcmp(k->key, &ECDSA_KEY_NULL, sizeof(ecc_key_t)))
			status = verify_signature(k->name, md, SHA512_DIGEST_LENGTH,
					*(k->sig), *(k->key)) && status;
		else
			if (verbose) printf("%s is NULL, skipping\n", k->name);
	}
	if (verbose) printf("\n");

	// Verify Payload hash.
	status = getPayloadHash(fdin, be64_to_cpu(c.sh->payload_size), md, 1)
			&& status;
	if (verbose) print_bytes((char *) "Payload hash = ", (uint8_t *) md,
			SHA512_DIGEST_LENGTH);

	if (memcmp((uint8_t *) c.sh->payload_hash, md, SHA512_DIGEST_LENGTH)) {
		if (verbose)
			printf("Payload hash does not agree with value in SW header: MISMATCH\n");
		status = false;
	} else {
		if (verbose)
			printf("Payload hash agrees with value in SW header: VERIFIED ./\n");
		status = status && true;
	}
	if (verbose) printf("\n");

	// Verify SW keys hash.
	p = SHA512(c.pd->sw_pkey_p, sizeof(ecc_key_t) * c.ph->sw_key_count, md);
	if (!p)
		die(EX_SOFTWARE, "%s", "Cannot get SHA512");
	if (verbose) print_bytes((char *) "SW keys hash = ", (uint8_t *) md,
			SHA512_DIGEST_LENGTH);

	if (memcmp((uint8_t *) c.ph->payload_hash, md, SHA512_DIGEST_LENGTH)) {
		if (verbose)
			printf("SW keys hash does not agree with value in Prefix header: MISMATCH\n");
		status = false;
	} else {
		if (verbose)
			printf("SW keys hash agrees with value in Prefix header: VERIFIED ./\n");
		status = status && true;
	}
	if (verbose) printf("\n");
	return status;
}


static bool validate_container_v2(struct parsed_stb_container_v2 c, int fdin)
{
	static int status = true;

	void *md = alloca(SHA512_DIGEST_LENGTH);
	void *p;
	size_t sSwKeySize = 0;

	// Get Prefix header hash.
	p = calc_hash(HASH_ALG_SHA3_512, (uint8_t *) c.ph, sizeof(ROM_prefix_header_v2_raw), md);
	if (!p)
		die(EX_SOFTWARE, "%s", "Cannot get SHA512");
	if (verbose) print_bytes((char *) "PR header hash = ", (uint8_t *) md,
			SHA512_DIGEST_LENGTH);

	// Verify HW key sigs.
	if (memcmp(&(c.c->hw_pkey_a), &ECDSA_KEY_NULL, sizeof(ecc_key_t))) {
		status = verify_signature("HW_key_A", md, SHA512_DIGEST_LENGTH,
					  c.pd->hw_sig_a, c.c->hw_pkey_a) && status;
	} else if (verbose) {
		printf("HW_key_A is NULL, skipping signature check.\n");
	}
	if (memcmp(&(c.c->hw_pkey_d), &ECDSA_KEY_NULL, sizeof(ecc_key_t))) {
		status = verify_dilithium_signature("HW_key_D", md, SHA512_DIGEST_LENGTH,
						    c.pd->hw_sig_d, c.c->hw_pkey_d) && status;
	} else if (verbose) {
		printf("HW_key_D is NULL, skipping signature check.\n");
	}
	if (verbose) printf("\n");

	// Get SW header hash.
	p = calc_hash(HASH_ALG_SHA3_512, (uint8_t *) c.sh, sizeof(ROM_sw_header_v2_raw), md);
	if (!p)
		die(EX_SOFTWARE, "%s", "Cannot get SHA512");
	if (verbose) print_bytes((char *) "SW header hash = ", (uint8_t *) md,
			SHA512_DIGEST_LENGTH);

	// Verify SW key sigs.
	if (memcmp(&(c.pd->sw_pkey_p), &ECDSA_KEY_NULL, sizeof(ecc_key_t))) {
		status = verify_signature("SW_key_P", md, SHA512_DIGEST_LENGTH,
					  c.ssig->sw_sig_p, c.pd->sw_pkey_p) && status;
		sSwKeySize += sizeof(ecc_key_t);
	} else if (verbose) {
		printf("%s is NULL, skipping\n", "SW_key_P");
	}
	if (memcmp(&(c.pd->sw_pkey_s), &ECDSA_KEY_NULL, sizeof(ecc_key_t))) {
		status = verify_dilithium_signature("SW_key_S", md, SHA512_DIGEST_LENGTH,
						    c.ssig->sw_sig_s, c.pd->sw_pkey_s) && status;
		sSwKeySize += sizeof(dilithium_key_t);
	} else if (verbose) {
		printf("%s is NULL, skipping\n", "SW_key_S");
	}
	if (verbose) printf("\n");

	// Verify Payload hash.
	status = getPayloadHash(fdin, be64_to_cpu(c.sh->payload_size), md, 2)
			&& status;
	if (verbose) print_bytes((char *) "Payload hash = ", (uint8_t *) md,
			SHA512_DIGEST_LENGTH);

	if (memcmp((uint8_t *) c.sh->payload_hash, md, SHA512_DIGEST_LENGTH)) {
		if (verbose)
			printf("Payload hash does not agree with value in SW header: MISMATCH\n");
		status = false;
	} else {
		if (verbose)
			printf("Payload hash agrees with value in SW header: VERIFIED ./\n");
		status = status && true;
	}
	if (verbose) printf("\n");

	// Verify SW keys hash.
	p = calc_hash(HASH_ALG_SHA3_512, c.pd->sw_pkey_p, sSwKeySize,md );
	if (!p)
		die(EX_SOFTWARE, "%s", "Cannot get SHA512");
	if (verbose) print_bytes((char *) "SW keys hash = ", (uint8_t *) md,
			SHA512_DIGEST_LENGTH);

	if (memcmp((uint8_t *) c.ph->payload_hash, md, SHA512_DIGEST_LENGTH)) {
		if (verbose)
			printf("SW keys hash does not agree with value in Prefix header: MISMATCH\n");
		status = false;
	} else {
		if (verbose)
			printf("SW keys hash agrees with value in Prefix header: VERIFIED ./\n");
		status = status && true;
	}
	if (verbose) printf("\n");
	return status;
}

static bool validate_container_v3(struct parsed_stb_container_v3 c, int fdin)
{
	static int status = true;

	void *md = alloca(SHA512_DIGEST_LENGTH);
	void *p;
	size_t sSwKeySize = 0;

	// Get Prefix header hash.
	p = calc_hash(HASH_ALG_SHA3_512, (uint8_t *) c.ph, sizeof(ROM_prefix_header_v3_raw), md);
	if (!p)
		die(EX_SOFTWARE, "%s", "Cannot get SHA512");
	if (verbose) print_bytes((char *) "PR header hash = ", (uint8_t *) md,
			SHA512_DIGEST_LENGTH);

	// Verify HW key sigs.
	if (memcmp(&(c.c->hw_pkey_a), &ECDSA_KEY_NULL, sizeof(ecc_key_t))) {
		status = verify_signature("HW_key_A", md, SHA512_DIGEST_LENGTH,
					  c.pd->hw_sig_a, c.c->hw_pkey_a) && status;
	} else if (verbose) {
		printf("HW_key_A is NULL, skipping signature check.\n");
	}
	if (memcmp(&(c.c->hw_pkey_d), &ECDSA_KEY_NULL, sizeof(ecc_key_t))) {
		status = verify_mldsa_87_signature("HW_key_D", md, SHA512_DIGEST_LENGTH,
						    c.pd->hw_sig_d, c.c->hw_pkey_d) && status;
	} else if (verbose) {
		printf("HW_key_D is NULL, skipping signature check.\n");
	}
	if (verbose) printf("\n");

	// Get SW header hash.
	p = calc_hash(HASH_ALG_SHA3_512, (uint8_t *) c.sh, sizeof(ROM_sw_header_v3_raw), md);
	if (!p)
		die(EX_SOFTWARE, "%s", "Cannot get SHA512");
	if (verbose) print_bytes((char *) "SW header hash = ", (uint8_t *) md,
			SHA512_DIGEST_LENGTH);

	// Verify SW key sigs.
	if (memcmp(&(c.pd->sw_pkey_p), &ECDSA_KEY_NULL, sizeof(ecc_key_t))) {
		status = verify_signature("SW_key_P", md, SHA512_DIGEST_LENGTH,
					  c.ssig->sw_sig_p, c.pd->sw_pkey_p) && status;
		sSwKeySize += sizeof(ecc_key_t);
	} else if (verbose) {
		printf("%s is NULL, skipping\n", "SW_key_P");
	}
	if (memcmp(&(c.pd->sw_pkey_s), &ECDSA_KEY_NULL, sizeof(ecc_key_t))) {
		status = verify_mldsa_87_signature("SW_key_S", md, SHA512_DIGEST_LENGTH,
						    c.ssig->sw_sig_s, c.pd->sw_pkey_s) && status;
		sSwKeySize += sizeof(mldsa_key_t);
	} else if (verbose) {
		printf("%s is NULL, skipping\n", "SW_key_S");
	}
	if (verbose) printf("\n");

	// Verify Payload hash.
	status = getPayloadHash(fdin, be64_to_cpu(c.sh->payload_size), md, 2)
			&& status;
	if (verbose) print_bytes((char *) "Payload hash = ", (uint8_t *) md,
			SHA512_DIGEST_LENGTH);

	if (memcmp((uint8_t *) c.sh->payload_hash, md, SHA512_DIGEST_LENGTH)) {
		if (verbose)
			printf("Payload hash does not agree with value in SW header: MISMATCH\n");
		status = false;
	} else {
		if (verbose)
			printf("Payload hash agrees with value in SW header: VERIFIED ./\n");
		status = status && true;
	}
	if (verbose) printf("\n");

	// Verify SW keys hash.
	p = calc_hash(HASH_ALG_SHA3_512, c.pd->sw_pkey_p, sSwKeySize,md );
	if (!p)
		die(EX_SOFTWARE, "%s", "Cannot get SHA512");
	if (verbose) print_bytes((char *) "SW keys hash = ", (uint8_t *) md,
			SHA512_DIGEST_LENGTH);

	if (memcmp((uint8_t *) c.ph->payload_hash, md, SHA512_DIGEST_LENGTH)) {
		if (verbose)
			printf("SW keys hash does not agree with value in Prefix header: MISMATCH\n");
		status = false;
	} else {
		if (verbose)
			printf("SW keys hash agrees with value in Prefix header: VERIFIED ./\n");
		status = status && true;
	}
	if (verbose) printf("\n");
	return status;
}

static bool verify_container(struct parsed_stb_container c, char * verify)
{
	static int status = false;

	void *md = alloca(SHA512_DIGEST_LENGTH);
	void *p;

	p = SHA512(c.c->hw_pkey_a, sizeof(ecc_key_t) * 3, md);
	if (!p)
		die(EX_SOFTWARE, "%s", "Cannot get SHA512");
	if (verbose) print_bytes((char *) "HW keys hash = ", (uint8_t *) md,
			SHA512_DIGEST_LENGTH);

	void *md_verify = alloca(SHA512_DIGEST_LENGTH);
	getVerificationHash(verify, md_verify, SHA512_DIGEST_LENGTH);

	if (memcmp((uint8_t *) md_verify, md, SHA512_DIGEST_LENGTH )) {
		if (verbose)
			printf("HW keys hash does not agree with provided value: MISMATCH\n");
	} else {
		if (verbose)
			printf("HW keys hash agrees with provided value: VERIFIED ./\n");
		status = true;
	}
	if (verbose) printf("\n");
	return status;
}

static bool verify_container_v2(struct parsed_stb_container_v2 c, char * verify)
{
	static int status = false;

	void *md = alloca(SHA512_DIGEST_LENGTH);
	void *p;

	p = calc_hash(HASH_ALG_SHA3_512, c.c->hw_pkey_a, sizeof(ecc_key_t) + sizeof(dilithium_key_t), md);
	if (!p)
		die(EX_SOFTWARE, "%s", "Cannot get SHA512");
	if (verbose) print_bytes((char *) "HW keys hash = ", (uint8_t *) md,
			SHA512_DIGEST_LENGTH);

	void *md_verify = alloca(SHA512_DIGEST_LENGTH);
	getVerificationHash(verify, md_verify, SHA512_DIGEST_LENGTH);

	if (memcmp((uint8_t *) md_verify, md, SHA512_DIGEST_LENGTH )) {
		if (verbose)
			printf("HW keys hash does not agree with provided value: MISMATCH\n");
	} else {
		if (verbose)
			printf("HW keys hash agrees with provided value: VERIFIED ./\n");
		status = true;
	}
	if (verbose) printf("\n");
	return status;
}

static bool verify_container_v3(struct parsed_stb_container_v3 c, char * verify)
{
	static int status = false;

	void *md = alloca(SHA512_DIGEST_LENGTH);
	void *p;

	p = calc_hash(HASH_ALG_SHA3_512, c.c->hw_pkey_a, sizeof(ecc_key_t) + sizeof(mldsa_key_t), md);
	if (!p)
		die(EX_SOFTWARE, "%s", "Cannot get SHA512");
	if (verbose) print_bytes((char *) "HW keys hash = ", (uint8_t *) md,
			SHA512_DIGEST_LENGTH);

	void *md_verify = alloca(SHA512_DIGEST_LENGTH);
	getVerificationHash(verify, md_verify, SHA512_DIGEST_LENGTH);

	if (memcmp((uint8_t *) md_verify, md, SHA512_DIGEST_LENGTH )) {
		if (verbose)
			printf("HW keys hash does not agree with provided value: MISMATCH\n");
	} else {
		if (verbose)
			printf("HW keys hash agrees with provided value: VERIFIED ./\n");
		status = true;
	}
	if (verbose) printf("\n");
	return status;
}

static bool verify_signature(const char *moniker, const unsigned char *dgst,
		int dgst_len, const ecc_signature_t sig_raw, const ecc_key_t key_raw)
{
	int r;
	bool status = false;

	// Convert the raw sig to a structure that can be handled by openssl.
	debug_print((char *) "Raw sig = ", (uint8_t *) sig_raw,
			sizeof(ecc_signature_t));

	BIGNUM *r_bn = BN_new();
	BIGNUM *s_bn = BN_new();

	BN_bin2bn((const unsigned char*) &sig_raw[0], 66, r_bn);
	BN_bin2bn((const unsigned char*) &sig_raw[66], 66, s_bn);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	ECDSA_SIG* ecdsa_sig = ECDSA_SIG_new();
	ECDSA_SIG_set0(ecdsa_sig, r_bn, s_bn);
#else
	ECDSA_SIG* ecdsa_sig = malloc(sizeof(ECDSA_SIG));
	ecdsa_sig->r = r_bn;
	ecdsa_sig->s = s_bn;
#endif

	// Convert the raw key to a structure that can be handled by openssl.
	debug_print((char *) "Raw key = ", (uint8_t *) key_raw,
			sizeof(ecc_key_t));

	EC_KEY *ec_key = EC_KEY_new();
	if (!ec_key)
		die(EX_SOFTWARE, "%s", "Cannot EC_KEY_new");

	const EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_secp521r1);
	if (!ec_group)
		die(EX_SOFTWARE, "%s", "Cannot EC_GROUP_new_by_curve_name");

	r = EC_KEY_set_group(ec_key, ec_group);
	if (r == 0)
		die(EX_SOFTWARE, "%s", "Cannot EC_KEY_set_group");

	// Add prefix 0x04, for uncompressed key.
	unsigned char *buffer = alloca(sizeof(ecc_key_t) + 1);
	*buffer = 0x04;
	memcpy(buffer + 1, key_raw, sizeof(ecc_key_t));

	BIGNUM *key_bn = BN_new();
	BN_bin2bn((const unsigned char*) buffer, EC_COORDBYTES * 2 + 1, key_bn);

	EC_POINT *ec_point = EC_POINT_bn2point(ec_group, key_bn, NULL, NULL);
	if (!ec_point)
		die(EX_SOFTWARE, "%s", "Cannot EC_POINT_bn2point");

	r = EC_KEY_set_public_key(ec_key, (const EC_POINT*) ec_point);
	if (r == 0)
		die(EX_SOFTWARE, "%s", "Cannot EC_KEY_set_public_key");

	// Verify the signature.
	r = ECDSA_do_verify(dgst, dgst_len, ecdsa_sig, ec_key);
	if (r == 1) {
		if (verbose) printf("%s signature is good: VERIFIED ./\n", moniker);
		status = true;
	} else if (r == 0) {
		if (verbose) printf("%s signature FAILED to verify.\n", moniker);
		status = false;
	} else {
		die(EX_SOFTWARE, "%s", "Cannot ECDSA_do_verify");
	}

	BN_free(key_bn);

	EC_KEY_free(ec_key);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	ECDSA_SIG_free(ecdsa_sig);
#else
	BN_free(r_bn);
	BN_free(s_bn);
	free(ecdsa_sig);
#endif
	return status;
}

static bool verify_dilithium_signature(const char *moniker, const unsigned char *dgst,
				       int dgst_len, const dilithium_signature_t sig_raw, const dilithium_key_t key_raw)
{
	bool sRet = false;
#ifdef ADD_DILITHIUM
	mlca_ctx_t sCtx;
	MLCA_RC    sMlRc = 0;

	sMlRc = mlca_init(&sCtx,1,0);
	if (sMlRc)
	{
		printf("**** ERROR : Failed mlca_init : %d\n", sMlRc);
	}
	if (0 == sMlRc)
	{
		sMlRc = mlca_set_alg(&sCtx, MLCA_ALGORITHM_SIG_DILITHIUM_R2_8x7_OID, OPT_LEVEL_AUTO);
		if (sMlRc)
		{
			printf("**** ERROR : Failed mlca_set_alg : %d\n", sMlRc);
		}
	}
	if (0 == sMlRc)
	{
		sMlRc = mlca_set_encoding_by_idx(&sCtx, 0);
		if (sMlRc)
		{
			printf("**** ERROR : Failed mlca_set_encoding_by_name_oid : %d\n", sMlRc);
		}
	}
	if (0 == sMlRc)
	{
		printf("Verifying Dilthium R2 8x7 signature ...\n");
		sMlRc = mlca_sig_verify(&sCtx, dgst, dgst_len, sig_raw, sizeof(dilithium_signature_t), key_raw);
		if (1 != sMlRc)
		{
			if (verbose) printf("%s signature FAILED to verify.\n", moniker);
			sRet = false;
		}
		else
		{
			if (verbose) printf("%s signature is good: VERIFIED ./\n", moniker);
			sRet = true;
		}
	}
#else
	die(EX_SOFTWARE, "%s", "Cannot Dilithium_do_verify");
#endif
	return sRet;
}

static bool verify_mldsa_87_signature(const char *moniker, const unsigned char *dgst,
				       int dgst_len, const mldsa_signature_t sig_raw, const mldsa_key_t key_raw)
{
	bool sRet = false;
#ifdef ADD_DILITHIUM
	mlca_ctx_t sCtx;
	MLCA_RC    sMlRc = 0;

	sMlRc = mlca_init(&sCtx,1,0);
	if (sMlRc)
	{
		printf("**** ERROR : Failed mlca_init : %d\n", sMlRc);
	}
	if (0 == sMlRc)
	{
		sMlRc = mlca_set_alg(&sCtx, MLCA_ALGORITHM_SIG_MLDSA_87, OPT_LEVEL_AUTO);
		if (sMlRc)
		{
			printf("**** ERROR : Failed mlca_set_alg : %d\n", sMlRc);
		}
	}
	if (0 == sMlRc)
	{
		sMlRc = mlca_set_encoding_by_idx(&sCtx, 0);
		if (sMlRc)
		{
			printf("**** ERROR : Failed mlca_set_encoding_by_name_oid : %d\n", sMlRc);
		}
	}
	if (0 == sMlRc)
	{
		printf("Verifying MLDSA-87 signature ...\n");
		sMlRc = mlca_sig_verify(&sCtx, dgst, dgst_len, sig_raw, sizeof(mldsa_signature_t), key_raw);
		if (1 != sMlRc)
		{
			if (verbose) printf("%s signature FAILED to verify.\n", moniker);
			sRet = false;
		}
		else
		{
			if (verbose) printf("%s signature is good: VERIFIED ./\n", moniker);
			sRet = true;
		}
	}
#else
	die(EX_SOFTWARE, "%s", "Cannot mldsa_do_verify");
#endif
	return sRet;
}

static bool getPayloadHash(int fdin, uint64_t pl_sz_expected, unsigned char *md, int container_version)
{
	struct stat st;
	void *file;
	int r;
	void *p;

	r = fstat(fdin, &st);
	if (r != 0)
		die(EX_NOINPUT, "Cannot stat payload file at descriptor: %d (%s)", fdin,
				strerror(errno));

	uint64_t pl_sz_actual = 0;
	if (container_version == 1)
	{
		pl_sz_actual = max(0, st.st_size - SECURE_BOOT_HEADERS_SIZE);
	}
	else if (container_version == 2)
	{
		pl_sz_actual = max(0, st.st_size - SECURE_BOOT_HEADERS_V2_SIZE);
	}
        else
        {
		pl_sz_actual = max(0, st.st_size - SECURE_BOOT_HEADERS_V3_SIZE);
        }
	if (verbose && (pl_sz_expected != pl_sz_actual))
		printf("Payload expected size = %lu, actual size = %lu\n\n",
				pl_sz_expected, pl_sz_actual);

	file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fdin, 0);
	if (file == MAP_FAILED)
		die(EX_OSERR, "Cannot mmap file at fd: %d, size: %lu (%s)", fdin,
				st.st_size, strerror(errno));

	if (container_version == 1)
	{
		p = SHA512(file + SECURE_BOOT_HEADERS_SIZE,
			   (params.ignore_remainder ?
			    min(pl_sz_actual, pl_sz_expected) : pl_sz_actual), md);
	} else if (container_version == 2) {
		p = calc_hash(HASH_ALG_SHA3_512, file + SECURE_BOOT_HEADERS_V2_SIZE,
			     (params.ignore_remainder ?
			      min(pl_sz_actual, pl_sz_expected) : pl_sz_actual), md);
	} else {
		p = calc_hash(HASH_ALG_SHA3_512, file + SECURE_BOOT_HEADERS_V3_SIZE,
			     (params.ignore_remainder ?
			      min(pl_sz_actual, pl_sz_expected) : pl_sz_actual), md);
	}
	if (!p)
		die(EX_SOFTWARE, "%s", "Cannot get SHA512");

	return true;
}

static bool getVerificationHash(char *input, unsigned char *md, int len)
{
	if (len < 0)
		die(EX_NOINPUT, "%s", "Expected len > 0");

	char buf[len * 2 + 1 + 2]; // allow trailing \n and leading "0x"
	char *p;

	// Initializing makes it clear to source code analyzers that the scope of
	// buf cannot be reduced; but p must be updated appropriately below.
	p = (char *) buf;

	if (isValidHex(input, len)) {
		p = input;
	} else {
		int fdin = open(input, O_RDONLY);
		if (fdin <= 0)
			die(EX_NOINPUT, "%s",
					"Verify requested but no valid hash or hash file provided");

		struct stat s;
		int r = fstat(fdin, &s);
		if (r != 0)
			die(EX_NOINPUT, "Cannot stat hash file: %s (%s)", input,
					strerror(errno));
		if ((size_t) s.st_size > (sizeof(buf)))
			die(EX_DATAERR,
					"Verify hash file \"%s\" invalid size: expected a %d byte hexadecimal value",
					input, len);

		r = read(fdin, buf, s.st_size);
		if (r <= 0)
			die(EX_NOINPUT, "Cannot read hash file: %s (%s)", input,
					strerror(errno));
		p = (char *) buf;

		for (unsigned int i = 0; i < sizeof(buf); i++) // strip newline char
			if (buf[i] == '\n')
				buf[i] = '\0';

		close(fdin);
	}

	// Convert hexascii to binary.
	if (isValidHex(p, len)) {
		if (!strncmp(p, "0x", 2)) // skip leading "0x"
			p += 2;
		for (int count = 0; count < len; count++) {
			sscanf(p, "%2hhx", &md[count]);
			p += 2;
		}
	} else
		die(EX_DATAERR,
				"Verify hash file \"%s\" invalid data: expected a %d byte hexadecimal value",
				input, len);

	return true;
}

__attribute__((__noreturn__)) static void usage (int status)
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
			" -d, --debug             show additional debug output\n"
			" -w, --wrap              column at which to wrap long output (wrap=0 => unlimited)\n"
			" -s, --stats             additionally print container stats\n"
			" -I, --imagefile         containerized image to display (input)\n"
			"     --validate          perform all checks to ensure is container valid for secure boot\n"
			"     --validate-ignore-remainder\n"
			"                         use the payload size in the container header when calculating\n"
			"                         payload hash, and ignore any trailing bytes or padding.\n"
			"     --verify            value, or filename containing value, of the HW Keys hash to\n"
			"                         verify the container against. must be valid 64 byte hexascii.\n"
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
	{ "stats",            no_argument,       0,  's' },
	{ "imagefile",        required_argument, 0,  'I' },
	{ "validate",         no_argument,       0,  '0' },
	{ "verify",           required_argument, 0,  '1' },
	{ "no-print",         no_argument,       0,  '2' },
	{ "print",            no_argument,       0,  '3' },
	{ "validate-ignore-remainder", no_argument, 0, '4' },
	{ NULL, 0, NULL, 0 }
};
#endif


int main(int argc, char* argv[])
{
	int r;
	struct stat st;
	void *container;
	struct parsed_stb_container c;
	struct parsed_stb_container_v2 c_v2;
        struct parsed_stb_container_v3 c_v3;
	int container_status = EX_OK;
	int validate_status = UNATTEMPTED;
	int verify_status = UNATTEMPTED;

	params.print_container = true;

	progname = strrchr(argv[0], '/');
	if (progname != NULL)
		++progname;
	else
		progname = argv[0];

#ifdef _AIX
	for (int i = 1; i < argc; i++) {
		if (!strcmp(*(argv + i), "--help")) {
			*(argv + i) = "-h";
		} else if (!strcmp(*(argv + i), "--verbose")) {
			*(argv + i) = "-v";
		} else if (!strcmp(*(argv + i), "--debug")) {
			*(argv + i) = "-d";
		} else if (!strcmp(*(argv + i), "--wrap")) {
			*(argv + i) = "-w";
		} else if (!strcmp(*(argv + i), "--stats")) {
			*(argv + i) = "-s";
		} else if (!strcmp(*(argv + i), "--imagefile")) {
			*(argv + i) = "-I";
		} else if (!strcmp(*(argv + i), "--validate")) {
			*(argv + i) = "-0";
		} else if (!strcmp(*(argv + i), "--verify")) {
			*(argv + i) = "-1";
		} else if (!strcmp(*(argv + i), "--no-print")) {
			*(argv + i) = "-2";
		} else if (!strcmp(*(argv + i), "--print")) {
			*(argv + i) = "-3";
		} else if (!strcmp(*(argv + i), "--validate-ignore-remainder")) {
			*(argv + i) = "-4";
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
		opt = getopt(argc, argv, "??hvdw:sI:01:23");
#else
		opt = getopt_long(argc, argv, "?hvdw:sI:01:23", opts, NULL);
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
		case 's':
			print_stats = true;
			break;
		case 'I':
			params.imagefn = optarg;
			break;
		case '0':
			params.validate = true;
			break;
		case '1':
			params.verify = optarg;
			break;
		case '2':
			params.print_container = false;
			break;
		case '3':
			params.print_container = true;
			break;
		case '4':
			params.ignore_remainder = true;
			break;
		default:
			usage(EX_USAGE);
		}
	}

	if (!params.imagefn) {
		fprintf(stderr, "No --imagefile provided, nothing to do.\n");
		usage(EX_USAGE);
	}
	int fdin = open(params.imagefn, O_RDONLY);
	if (fdin <= 0)
		die(EX_NOINPUT, "Cannot open container file: %s (%s)", params.imagefn,
				strerror(errno));

	r = fstat(fdin, &st);
	if (r != 0)
		die(EX_NOINPUT, "Cannot stat container file: %s (%s)", params.imagefn,
				strerror(errno));

	if (st.st_size == 0)
		die(EX_NOINPUT, "%s", "Container file is empty, nothing to do.");

	if (st.st_size < SECURE_BOOT_HEADERS_SIZE)
		fprintf(stderr,
				"Warning: container file \"%s\" smaller than minimum header size, file may be incomplete.\n",
				params.imagefn);

	container = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fdin, 0);
	if (container == MAP_FAILED)
		die(EX_OSERR, "Cannot mmap file at fd: %d, size: %lu (%s)", fdin,
				st.st_size, strerror(errno));

	if (!stb_is_container(container, st.st_size))
		die(EX_DATAERR, "%s", "Not a container, missing magic number");

	if (!stb_is_v2_container(container, st.st_size) && !stb_is_v3_container(container, st.st_size))
	{
		if (parse_stb_container(container, SECURE_BOOT_HEADERS_SIZE, &c) != 0)
			die(EX_DATAERR, "%s", "Failed to parse container");

		if (params.print_container)
			display_container(c);

		if (params.validate)
			validate_status = validate_container(c, fdin);

		if (params.verify)
			verify_status = verify_container(c, params.verify);

	}
	else if (stb_is_v2_container(container, st.st_size))
	{
#ifndef ADD_DILITHIUM
		die(EX_SOFTWARE, "%s", "print-container must be built with ADD_DILITHIUM for v2 containers");
#elif OPENSSL_VERSION_NUMBER < 0x10100000L
		die(EX_NOINPUT, "Invalid container version due to downlevel openssl version : %d", 2);
#endif
		if (parse_stb_container_v2(container, SECURE_BOOT_HEADERS_V2_SIZE, &c_v2) != 0)
			die(EX_DATAERR, "%s", "Failed to parse container");

		if (params.print_container)
			display_container_v2(c_v2);

		if (params.validate)
			validate_status = validate_container_v2(c_v2, fdin);

		if (params.verify)
			verify_status = verify_container_v2(c_v2, params.verify);
	}
	else if (stb_is_v3_container(container, st.st_size))
	{
#ifndef ADD_DILITHIUM
		die(EX_SOFTWARE, "%s", "print-container must be built with ADD_DILITHIUM for v3 containers");
#elif OPENSSL_VERSION_NUMBER < 0x10100000L
		die(EX_NOINPUT, "Invalid container version due to downlevel openssl version : %d", 3);
#endif
		if (parse_stb_container_v3(container, SECURE_BOOT_HEADERS_V3_SIZE, &c_v3) != 0)
			die(EX_DATAERR, "%s", "Failed to parse container");

		if (params.print_container)
			display_container_v3(c_v3);

		if (params.validate)
			validate_status = validate_container_v3(c_v3, fdin);

		if (params.verify)
			verify_status = verify_container_v3(c_v3, params.verify);
	}
	if ((validate_status != UNATTEMPTED) || (verify_status != UNATTEMPTED)) {
		printf("Container validity check %s. Container verification check %s.\n\n",
				(validate_status == UNATTEMPTED) ?
						"not attempted" :
						((validate_status == PASSED) ? "PASSED" : "FAILED"),
				(verify_status == UNATTEMPTED) ?
						"not attempted" :
						((verify_status == PASSED) ? "PASSED" : "FAILED"));

		if ((validate_status == FAILED) || (verify_status == FAILED))
			container_status = 1;
	}

	close(fdin);
	return container_status;
}
