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

#include "container.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <regex.h>
#include <sysexits.h>

extern char *progname;

extern bool verbose, debug;
extern int wrap;

#define die(status, msg, ...) \
        { fprintf(stderr, "error: %s.%s() line %d: " msg "\n", progname, \
        		__func__, __LINE__, __VA_ARGS__); exit(status); }

#define debug_msg(msg, ...) \
        if (debug) fprintf(stderr, "--> %s.%s(): " msg "\n", progname, \
        		__func__, __VA_ARGS__);

#define verbose_msg(msg, ...) \
        if (verbose) fprintf(stdout, "--> %s: " msg "\n", progname, \
        		__VA_ARGS__);

void hex_print(char *lead, unsigned char *buffer, size_t buflen)
{
	unsigned int i, indent = 4;
	char prelead[100];
	snprintf(prelead, 100, "--> %s: ", progname);

	char *pad = (((strlen(prelead) + strlen(lead)) % 2) == 0) ? "" : " ";
	wrap = ((wrap % 2) == 0) ? wrap : wrap - 1;
	indent = ((indent % 2) == 0) ? indent : indent - 1;
	int col = fprintf(stdout, "%s%s%s", prelead, lead, pad);
	for (i = 1; i < buflen + 1; i++) {
		fprintf(stdout, "%02x", buffer[i - 1]);
		col = col + 2;
		if (((col % wrap) == 0) && (i < buflen)) {
			fprintf(stdout, "\n%*c", indent, ' ');
			col = indent;
		}
	}
	fprintf(stdout, "\n");
}

void verbose_print(char *lead, unsigned char *buffer, size_t buflen)
{
	if (verbose)
		hex_print(lead, buffer, buflen);
}

void debug_print(char *lead, unsigned char *buffer, size_t buflen)
{
	if (debug)
		hex_print(lead, buffer, buflen);
}

/**
 * Validate hexadecimal ASCII input of a given length.
 * - len is the byte len of the resulting value, not the len of the hexascii.
 * - len = 0 means validate input of arbitrary length.
*/
int isValidHex(char *input, int len) {
	int r;
	size_t maxlen = 512; // sane limit
	regex_t regexpr;
	char pattern[48];
	char multiplier[8];
	bool result = false;

	if ((strnlen(input, maxlen) > maxlen * 2) || (len > (int) maxlen))
		die(EX_DATAERR, "input exceeded max length: %lu", maxlen);

	if (len > 0)
		sprintf(multiplier, "{%d}", len * 2); // allow this (byte) len only
	else
		sprintf(multiplier, "+"); // unlimited

	sprintf(pattern, "^(0x|0X)?[a-fA-F0-9]%s$", multiplier);

	if ((r = regcomp(&regexpr, pattern, REG_EXTENDED | REG_NOSUB)))
		die(EX_SOFTWARE, "%s", "failure to compile regex");

	if (!(r = regexec(&regexpr, input, 0, NULL, 0)))
		result = true;

	regfree(&regexpr);
	return result;
}

/**
 * Validate ASCII input up to a given length.
 * - len is the expected len of the ascii input.
 * - len = 0 means validate input of arbitrary length.
 * - NOTE: not all ascii chars are allowed here.
 */
int isValidAscii(char *input, int len) {
	int r;
	size_t maxlen = 256; // sane limit
	regex_t regexpr;
	char pattern[48];
	char multiplier[8];
	bool result = false;

	if ((strnlen(input, maxlen) > maxlen) || (len > (int) maxlen))
		die(EX_DATAERR, "input exceeded max length: %lu", maxlen);

	if (len > 0)
		sprintf(multiplier, "{,%d}", len);  // allow *up to* this len
	else
		sprintf(multiplier, "+"); // unlimited

	sprintf(pattern, "^[a-zA-Z0-9_+-]%s$", multiplier);

	if ((r = regcomp(&regexpr, pattern, REG_EXTENDED | REG_NOSUB)))
		die(EX_SOFTWARE, "%s", "failure to compile regex");

	if (!(r = regexec(&regexpr, input, 0, NULL, 0)))
		result = true;

	regfree(&regexpr);
	return result;
}
