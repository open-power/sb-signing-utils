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

#include <stdbool.h>
#include "container.h"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <sysexits.h>

char *progname;

bool print_stats;
bool verbose, debug;
int wrap = 100;

void usage(int status);

void print_bytes(char *lead, uint8_t *buffer, size_t buflen)
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

int parse_stb_container(const void* data, size_t len, struct parsed_stb_container *c)
{
	const size_t prefix_data_min_size = 3 * (EC_COORDBYTES * 2);
	c->buf = data;
	c->bufsz = len;
	c->c = data;
	c->ph = data += sizeof(ROM_container_raw);
	c->pd = data += sizeof(ROM_prefix_header_raw) + (c->ph->ecid_count * ECID_SIZE);
	c->sh = data += prefix_data_min_size + c->ph->sw_key_count * (EC_COORDBYTES * 2);
	c->ssig = data += sizeof(ROM_sw_header_raw) +
		c->sh->ecid_count * ECID_SIZE;

	return 0;
}

static void display_version_raw(const ROM_version_raw v)
{
	printf("ver_alg:\n");
	printf("  version:  %04x\n", be16_to_cpu(v.version));
	printf("  hash_alg: %02x (%s)\n", v.hash_alg, (v.hash_alg == 1)? "SHA512" : "UNKNOWN");
	printf("  sig_alg:  %02x (%s)\n", v.sig_alg, (v.sig_alg == 1) ? "SHA512/ECDSA-521" : "UNKNOWN");
}

static void display_prefix_header(const ROM_prefix_header_raw *p)
{
	printf("Prefix Header:\n");
	display_version_raw(p->ver_alg);
	printf("code_start_offset: %08lx\n", be64_to_cpu(p->code_start_offset));
	printf("reserved:          %08lx\n", be64_to_cpu(p->reserved));
	printf("flags:             %08x\n", be32_to_cpu(p->flags));
	printf("sw_key_count:      %02x\n", p->sw_key_count);
	printf("payload_size:      %08lx\n", be64_to_cpu(p->payload_size));
	print_bytes((char *) "payload_hash:      ", (uint8_t *) p->payload_hash,
			sizeof(p->payload_hash));
	printf("ecid_count:        %02x\n", p->ecid_count);

	for (int i = 0; i < p->ecid_count; i++) {
		printf("ecid:              ");
		print_bytes((char *) "ecid:              ", (uint8_t *) p->ecid[i].ecid,
				sizeof(p->ecid[i].ecid));
		printf("\n");
	}
}

static void display_sw_header(const ROM_sw_header_raw *swh)
{
	printf("Software Header:\n");
	display_version_raw(swh->ver_alg);
	printf("code_start_offset: %08lx\n", be64_to_cpu(swh->code_start_offset));
	printf("reserved:          %08lx\n", be64_to_cpu(swh->reserved));
	printf("flags:             %08x\n", be32_to_cpu(swh->flags));
	printf("reserved_0:        %02x\n", swh->reserved_0);
	printf("payload_size:      %08lx (%lu)\n", be64_to_cpu(swh->payload_size),
			be64_to_cpu(swh->payload_size));
	print_bytes((char *) "payload_hash:      ", (uint8_t *) swh->payload_hash,
			sizeof(swh->payload_hash));
	printf("ecid_count:        %02x\n", swh->ecid_count);

	for (int i = 0; i < swh->ecid_count; i++) {
		printf("ecid:              ");
		print_bytes((char *) "ecid:              ",
				(uint8_t *) swh->ecid[i].ecid, sizeof(swh->ecid[i].ecid));
		printf("\n");
	}
}

static void display_prefix_data(const int sw_key_count, const ROM_prefix_data_raw *pd)
{
	printf("Prefix Data:\n");
	print_bytes((char *) "hw_sig_a:  ", (uint8_t *) pd->hw_sig_a, sizeof(pd->hw_sig_a));
	print_bytes((char *) "hw_sig_b:  ", (uint8_t *) pd->hw_sig_b, sizeof(pd->hw_sig_b));
	print_bytes((char *) "hw_sig_c:  ", (uint8_t *) pd->hw_sig_c, sizeof(pd->hw_sig_c));
	if (sw_key_count >=1)
		print_bytes((char *) "sw_pkey_p: ", (uint8_t *) pd->sw_pkey_p, sizeof(pd->sw_pkey_p));
	if (sw_key_count >=2)
		print_bytes((char *) "sw_pkey_q: ", (uint8_t *) pd->sw_pkey_q, sizeof(pd->sw_pkey_q));
	if (sw_key_count >=3)
		print_bytes((char *) "sw_pkey_r: ", (uint8_t *) pd->sw_pkey_r, sizeof(pd->sw_pkey_r));
}

static void display_sw_sig(const ROM_sw_sig_raw *s)
{
	printf("Software Signatures:\n");
	print_bytes((char *) "sw_sig_p:  ", (uint8_t *) s->sw_sig_p, sizeof(s->sw_sig_p));
	print_bytes((char *) "sw_sig_q:  ", (uint8_t *) s->sw_sig_q, sizeof(s->sw_sig_q));
	print_bytes((char *) "sw_sig_r:  ", (uint8_t *) s->sw_sig_r, sizeof(s->sw_sig_r));
}

static void display_rom_container_raw(const ROM_container_raw *rcr)
{
	printf("Container:\n");
	printf("magic:          0x%04x\n", be32_to_cpu(rcr->magic_number));
	printf("version:        0x%02x\n", be16_to_cpu(rcr->version));
	printf("container_size: 0x%08lx (%lu)\n", be64_to_cpu(rcr->container_size), be64_to_cpu(rcr->container_size));
	printf("target_hrmor:   0x%08lx\n", be64_to_cpu(rcr->target_hrmor));
	printf("stack_pointer:  0x%08lx\n", be64_to_cpu(rcr->stack_pointer));
	print_bytes((char *) "hw_pkey_a: ", (uint8_t *) rcr->hw_pkey_a, sizeof(rcr->hw_pkey_a));
	print_bytes((char *) "hw_pkey_b: ", (uint8_t *) rcr->hw_pkey_b, sizeof(rcr->hw_pkey_b));
	print_bytes((char *) "hw_pkey_c: ", (uint8_t *) rcr->hw_pkey_c, sizeof(rcr->hw_pkey_c));
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
}

static void display_container(char* f)
{
	int fd = open(f, O_RDONLY);
	void *container = malloc(SECURE_BOOT_HEADERS_SIZE);
	struct parsed_stb_container c;
	size_t sz;

	assert(container);
	if (fd == -1) {
		perror(strerror(errno));
		exit(EXIT_FAILURE);
	}

	sz = read(fd, container, SECURE_BOOT_HEADERS_SIZE);
	if (sz != SECURE_BOOT_HEADERS_SIZE) {
		perror(strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (!stb_is_container(container, SECURE_BOOT_HEADERS_SIZE)) {
		fprintf(stderr, "Not a container, missing magic number\n");
		exit(EXIT_FAILURE);
	}

	if (parse_stb_container(container, SECURE_BOOT_HEADERS_SIZE, &c) != 0) {
		fprintf(stderr, "Failed to parse container.\n");
		exit(EXIT_FAILURE);
	}

	display_rom_container_raw(c.c);
	printf("\n");

	display_prefix_header(c.ph);
	printf("\n");

	display_prefix_data(c.ph->sw_key_count, c.pd);
	printf("\n");

	display_sw_header(c.sh);
	printf("\n");

	display_sw_sig(c.ssig);
	printf("\n");

	if (print_stats)
	display_container_stats(&c);

	free(container);
	close(fd);
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
			" -d, --debug             show additional debug output\n"
			" -w, --wrap              column at which to wrap long output (wrap=0 => unlimited)\n"
			" -s, --stats             additionally print container stats\n"
			" -I, --imagefile         containerized image to display (input)\n"
			"\n");
	};
	exit(status);
}

static struct option const opts[] = {
	{ "help",             no_argument,       0,  'h' },
	{ "verbose",          no_argument,       0,  'v' },
	{ "debug",            no_argument,       0,  'd' },
	{ "wrap",             required_argument, 0,  'w' },
	{ "stats",            no_argument,       0,  's' },
	{ "imagefile",        required_argument, 0,  'I' },
	{}
};

static struct {
	char *imagefn;
} params;


int main(int argc, char* argv[])
{
	int indexptr;

	progname = strrchr (argv[0], '/');
	if (progname != NULL)
		++progname;
	else
		progname = argv[0];

	while (1) {
		int opt;
		opt = getopt_long(argc, argv, "hvdw:sI:", opts, &indexptr);
		if (opt == -1)
			break;

		switch (opt) {
		case 'h':
		case '?':
			usage(EX_OK);
			break;
		case 'v':
			verbose = true;
			break;
		case 'd':
			debug = true;
			break;
		case 'w':
			wrap = atoi(optarg);
			break;
		case 's':
			print_stats = true;
			break;
		case 'I':
			params.imagefn = optarg;
			break;
		default:
			usage(EX_USAGE);
		}
	}

	display_container(params.imagefn);

	return 0;
}
