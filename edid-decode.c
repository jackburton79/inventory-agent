/*
 * Copyright 2006-2012 Red Hat, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * on the rights to use, copy, modify, merge, publish, distribute, sub
 * license, and/or sell copies of the Software, and to permit persons to whom
 * the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
/* Author: Adam Jackson <ajax@nwnk.net> */
/* Maintainer: Hans Verkuil <hverkuil-cisco@xs4all.nl> */

/* Other changes by Stefano Ceccherini */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <math.h>


#include "EDID.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))

enum {
	EDID_PAGE_SIZE = 128u
};

static int edid_minor = 0;
static int claims_one_point_oh = 0;
static int claims_one_point_two = 0;
static int claims_one_point_three = 0;
static int claims_one_point_four = 0;
static int nonconformant_digital_display = 0;
static int nonconformant_extension = 0;
static int did_detailed_timing = 0;
static int has_name_descriptor = 0;
static int has_serial_string = 0;
static int has_ascii_string = 0;
static int has_range_descriptor = 0;
static int has_preferred_timing = 0;
static int has_valid_checksum = 1;
static int has_valid_cta_checksum = 1;
static int has_valid_displayid_checksum = 1;
static int has_valid_cvt = 1;
static int has_valid_dummy_block = 1;
static int has_valid_serial_number = 0;
static int has_valid_serial_string = 0;
static int has_valid_name_descriptor = 0;
static int has_valid_week = 0;
static int has_valid_year = 0;
static int has_valid_detailed_blocks = 0;
static int has_valid_descriptor_ordering = 1;
static int has_valid_descriptor_pad = 1;
static int has_valid_range_descriptor = 1;
static int has_valid_max_dotclock = 1;
static int has_valid_string_termination = 1;
static int empty_string = 0;
static int trailing_space = 0;
static int has_cta861 = 0;
static int has_640x480p60_est_timing = 0;
static int has_cta861_vic_1 = 0;
static int manufacturer_name_well_formed = 0;
static int seen_non_detailed_descriptor = 0;

static int warning_excessive_dotclock_correction = 0;
static int nonconformant_hf_vsdb_position = 0;
static int nonconformant_srgb_chromaticity = 0;
static int nonconformant_cta861_640x480 = 0;
static int nonconformant_hdmi_vsdb_tmds_rate = 0;

static int min_hor_freq_hz = 0xfffffff;
static int max_hor_freq_hz = 0;
static int min_vert_freq_hz = 0xfffffff;
static int max_vert_freq_hz = 0;
static int max_pixclk_khz = 0;
static int mon_min_hor_freq_hz = 0;
static int mon_max_hor_freq_hz = 0;
static int mon_min_vert_freq_hz = 0;
static int mon_max_vert_freq_hz = 0;
static int mon_max_pixclk_khz = 0;
static unsigned supported_hdmi_vic_codes = 0;

static char serial_string[26];
static char model_string[13];

enum output_format {
	OUT_FMT_DEFAULT,
	OUT_FMT_HEX,
	OUT_FMT_RAW,
	OUT_FMT_CARRAY
};			


struct value {
	int value;
	const char *description;
};

struct field {
	const char *name;
	int start, end;
	struct value *values;
	int n_values;
};

#define DEFINE_FIELD(n, var, s, e, ...)				\
static struct value var##_values[] =  {				\
	__VA_ARGS__						\
};								\
static struct field var = {					\
	.name = n,						\
	.start = s,		        			\
	.end = e,						\
	.values = var##_values,	        			\
	.n_values = ARRAY_SIZE(var##_values),			\
}

static void decode_value(struct field *field, int val, const char *prefix)
{
	struct value *v;
	int i;

	for (i = 0; i < field->n_values; i++) {
		v = &field->values[i];

		if (v->value == val)
			break;
	}

	if (i == field->n_values) {
		return;
	}
}

static void _decode(struct field **fields, int n_fields, int data, const char *prefix)
{
	int i;

	for (i = 0; i < n_fields; i++) {
		struct field *f = fields[i];
		int field_length = f->end - f->start + 1;
		int val;

		if (field_length == 32)
			val = data;
		else
			val = (data >> f->start) & ((1 << field_length) - 1);

		decode_value(f, val, prefix);
	}
}

#define decode(fields, data, prefix)    \
	_decode(fields, ARRAY_SIZE(fields), data, prefix)

static char *manufacturer_name(const unsigned char *x)
{
	static char name[4];

	name[0] = ((x[0] & 0x7C) >> 2) + '@';
	name[1] = ((x[0] & 0x03) << 3) + ((x[1] & 0xE0) >> 5) + '@';
	name[2] = (x[1] & 0x1F) + '@';
	name[3] = 0;
							
	if (isupper(name[0]) && isupper(name[1]) && isupper(name[2]))
		manufacturer_name_well_formed = 1;

	return name;
}

/*
 * Copied from xserver/hw/xfree86/modes/xf86cvt.c
 */
static void edid_cvt_mode(int HDisplay, int VDisplay,
			  int VRefresh, int Reduced,
			  unsigned *MinHFreq, unsigned *MaxHFreq,
			  unsigned *MaxClock)
{
	/* 1) top/bottom margin size (% of height) - default: 1.8 */
#define CVT_MARGIN_PERCENTAGE 1.8

	/* 2) character cell horizontal granularity (pixels) - default 8 */
#define CVT_H_GRANULARITY 8

	/* 4) Minimum vertical porch (lines) - default 3 */
#define CVT_MIN_V_PORCH 3

	/* 4) Minimum number of vertical back porch lines - default 6 */
#define CVT_MIN_V_BPORCH 6

	/* Pixel Clock step (kHz) */
#define CVT_CLOCK_STEP 250

	float HPeriod;
	unsigned HTotal, Clock, HorFreq;
	int VSync;

	/* 2. Horizontal pixels */
	HDisplay = HDisplay - (HDisplay % CVT_H_GRANULARITY);

	/* Determine VSync Width from aspect ratio */
	if (!(VDisplay % 3) && ((VDisplay * 4 / 3) == HDisplay))
		VSync = 4;
	else if (!(VDisplay % 9) && ((VDisplay * 16 / 9) == HDisplay))
		VSync = 5;
	else if (!(VDisplay % 10) && ((VDisplay * 16 / 10) == HDisplay))
		VSync = 6;
	else if (!(VDisplay % 4) && ((VDisplay * 5 / 4) == HDisplay))
		VSync = 7;
	else if (!(VDisplay % 9) && ((VDisplay * 15 / 9) == HDisplay))
		VSync = 7;
	else                        /* Custom */
		VSync = 10;

	if (!Reduced) {             /* simplified GTF calculation */

		/* 4) Minimum time of vertical sync + back porch interval (µs)
		 * default 550.0 */
#define CVT_MIN_VSYNC_BP 550.0

		/* 3) Nominal HSync width (% of line period) - default 8 */
#define CVT_HSYNC_PERCENTAGE 8

		float HBlankPercentage;
		int HBlank;

		/* 8. Estimated Horizontal period */
		HPeriod = ((float) (1000000.0 / VRefresh - CVT_MIN_VSYNC_BP)) /
			(VDisplay + CVT_MIN_V_PORCH);

		/* 5) Definition of Horizontal blanking time limitation */
		/* Gradient (%/kHz) - default 600 */
#define CVT_M_FACTOR 600

		/* Offset (%) - default 40 */
#define CVT_C_FACTOR 40

		/* Blanking time scaling factor - default 128 */
#define CVT_K_FACTOR 128

		/* Scaling factor weighting - default 20 */
#define CVT_J_FACTOR 20

#define CVT_M_PRIME (CVT_M_FACTOR * CVT_K_FACTOR / 256)
#define CVT_C_PRIME ((CVT_C_FACTOR - CVT_J_FACTOR) * CVT_K_FACTOR / 256 + CVT_J_FACTOR)

		/* 12. Find ideal blanking duty cycle from formula */
		HBlankPercentage = CVT_C_PRIME - CVT_M_PRIME * HPeriod / 1000.0;

		/* 13. Blanking time */
		if (HBlankPercentage < 20)
			HBlankPercentage = 20;

		HBlank = HDisplay * HBlankPercentage / (100.0 - HBlankPercentage);
		HBlank -= HBlank % (2 * CVT_H_GRANULARITY);

		/* 14. Find total number of pixels in a line. */
		HTotal = HDisplay + HBlank;
	}
	else {                      /* Reduced blanking */
		/* Minimum vertical blanking interval time (µs) - default 460 */
#define CVT_RB_MIN_VBLANK 460.0

		/* Fixed number of clocks for horizontal sync */
#define CVT_RB_H_SYNC 32.0

		/* Fixed number of clocks for horizontal blanking */
#define CVT_RB_H_BLANK 160.0

		/* Fixed number of lines for vertical front porch - default 3 */
#define CVT_RB_VFPORCH 3

		int VBILines;

		/* 8. Estimate Horizontal period. */
		HPeriod = ((float) (1000000.0 / VRefresh - CVT_RB_MIN_VBLANK)) / VDisplay;

		/* 9. Find number of lines in vertical blanking */
		VBILines = ((float) CVT_RB_MIN_VBLANK) / HPeriod + 1;

		/* 10. Check if vertical blanking is sufficient */
		if (VBILines < (CVT_RB_VFPORCH + VSync + CVT_MIN_V_BPORCH))
			VBILines = CVT_RB_VFPORCH + VSync + CVT_MIN_V_BPORCH;

		/* 12. Find total number of pixels in a line */
		HTotal = HDisplay + CVT_RB_H_BLANK;
	}

	/* 15/13. Find pixel clock frequency (kHz for xf86) */
	Clock = HTotal * 1000.0 / HPeriod;
	Clock -= Clock % CVT_CLOCK_STEP;
	HorFreq = (Clock * 1000) / HTotal;

	*MinHFreq = min(*MinHFreq, HorFreq);
	*MaxHFreq = max(*MaxHFreq, HorFreq);
	*MaxClock = max(*MaxClock, Clock);
	min_hor_freq_hz = min(min_hor_freq_hz, HorFreq);
	max_hor_freq_hz = max(max_hor_freq_hz, HorFreq);
	max_pixclk_khz = max(max_pixclk_khz, Clock);
}

static int detailed_cvt_descriptor(const unsigned char *x, int first)
{
	const unsigned char empty[3] = { 0, 0, 0 };
	int width, height;
	int valid = 1;
	int fifty = 0, sixty = 0, seventyfive = 0, eightyfive = 0, reduced = 0;
	int min_refresh = 0xfffffff, max_refresh = 0;
	char* ratio = "";
	if (!first && !memcmp(x, empty, 3))
		return valid;

	height = x[0];
	height |= (x[1] & 0xf0) << 4;
	height++;
	height *= 2;

	switch (x[1] & 0x0c) {
	case 0x00:
		width = 8 * (((height * 4) / 3) / 8);
		ratio = "4:3";
		break;
	case 0x04:
		width = 8 * (((height * 16) / 9) / 8);
		ratio = "16:9";
		break;
	case 0x08:
		width = 8 * (((height * 16) / 10) / 8);
		ratio = "16:10";
		break;
	case 0x0c:
		width = 8 * (((height * 15) / 9) / 8);
		ratio = "15:9";
		break;
	}

	if (x[1] & 0x03)
		valid = 0;
	if (x[2] & 0x80)
		valid = 0;
	if (!(x[2] & 0x1f))
		valid = 0;

	fifty	= (x[2] & 0x10);
	sixty	= (x[2] & 0x08);
	seventyfive = (x[2] & 0x04);
	eightyfive  = (x[2] & 0x02);
	reduced	= (x[2] & 0x01);

	min_refresh = (fifty ? 50 : (sixty ? 60 : (seventyfive ? 75 : (eightyfive ? 85 : min_refresh))));
	max_refresh = (eightyfive ? 85 : (seventyfive ? 75 : (sixty ? 60 : (fifty ? 50 : max_refresh))));

	if (valid) {
		unsigned min_hfreq = ~0;
		unsigned max_hfreq = 0;
		unsigned max_clock = 0;

		min_vert_freq_hz = min(min_vert_freq_hz, min_refresh);
		max_vert_freq_hz = max(max_vert_freq_hz, max_refresh);

		if (fifty)
			edid_cvt_mode(width, height, 50, 0,
				      &min_hfreq, &max_hfreq, &max_clock);
		if (sixty)
			edid_cvt_mode(width, height, 60, 0,
				      &min_hfreq, &max_hfreq, &max_clock);
		if (seventyfive)
			edid_cvt_mode(width, height, 75, 0,
				      &min_hfreq, &max_hfreq, &max_clock);
		if (eightyfive)
			edid_cvt_mode(width, height, 75, 0,
				      &min_hfreq, &max_hfreq, &max_clock);
		if (reduced)
			edid_cvt_mode(width, height, 60, 1,
				      &min_hfreq, &max_hfreq, &max_clock);
	}

	(void)ratio;

	return valid;
}

/* extract a string from a detailed subblock, checking for termination */
static char *extract_string(const unsigned char *x, int *valid, int len)
{
	static char ret[EDID_PAGE_SIZE];
	int i, seen_newline = 0;

	memset(ret, 0, sizeof(ret));
	*valid = 1;

	for (i = 0; i < len; i++) {
		if (isgraph(x[i])) {
			ret[i] = x[i];
		} else if (!seen_newline) {
			if (x[i] == 0x0a) {
				seen_newline = 1;
				if (!i) {
					empty_string = 1;
					*valid = 0;
				} else if (ret[i - 1] == 0x20) {
					trailing_space = 1;
					*valid = 0;
				}
			} else if (x[i] == 0x20) {
				ret[i] = x[i];
			} else {
				has_valid_string_termination = 0;
				*valid = 0;
				return ret;
			}
		} else if (x[i] != 0x20) {
			has_valid_string_termination = 0;
			*valid = 0;
			return ret;
		}
	}
	/* Does the string end with a space? */
	if (!seen_newline && ret[len - 1] == 0x20) {
		trailing_space = 1;
		*valid = 0;
	}

	return ret;
}

static const struct {
	int x, y, refresh, ratio_w, ratio_h;
	int hor_freq_hz, pixclk_khz, interlaced;
} established_timings[] = {
	/* 0x23 bit 7 - 0 */
	{720, 400, 70, 9, 5, 31469, 28320},
	{720, 400, 88, 9, 5, 39500, 35500},
	{640, 480, 60, 4, 3, 31469, 25175},
	{640, 480, 67, 4, 3, 35000, 30240},
	{640, 480, 72, 4, 3, 37900, 31500},
	{640, 480, 75, 4, 3, 37500, 31500},
	{800, 600, 56, 4, 3, 35200, 36000},
	{800, 600, 60, 4, 3, 37900, 40000},
	/* 0x24 bit 7 - 0 */
	{800, 600, 72, 4, 3, 48100, 50000},
	{800, 600, 75, 4, 3, 46900, 49500},
	{832, 624, 75, 4, 3, 49726, 57284},
	{1280, 768, 87, 5, 3, 35522, 44900, 1},
	{1024, 768, 60, 4, 3, 48400, 65000},
	{1024, 768, 70, 4, 3, 56500, 75000},
	{1024, 768, 75, 4, 3, 60000, 78750},
	{1280, 1024, 75, 5, 4, 80000, 135000},
	/* 0x25 bit 7*/
	{1152, 870, 75, 192, 145, 67500, 108000},
};

static const struct {
	int x, y, refresh, ratio_w, ratio_h;
	int hor_freq_hz, pixclk_khz, rb;
} established_timings3[] = {
	/* 0x06 bit 7 - 0 */
	{640, 350, 85, 64, 35, 37900, 31500},
	{640, 400, 85, 16, 10, 37900, 31500},
	{720, 400, 85, 9, 5, 37900, 35500},
	{640, 480, 85, 4, 3, 43300, 36000},
	{848, 480, 60, 53, 30, 31000, 33750},
	{800, 600, 85, 4, 3, 53700, 56250},
	{1024, 768, 85, 4, 3, 68700, 94500},
	{1152, 864, 75, 4, 3, 67500, 108000},
	/* 0x07 bit 7 - 0 */
	{1280, 768, 60, 5, 3, 47400, 68250, 1},
	{1280, 768, 60, 5, 3, 47800, 79500},
	{1280, 768, 75, 5, 3, 60300, 102250},
	{1280, 768, 85, 5, 3, 68600, 117500},
	{1280, 960, 60, 4, 3, 60000, 108000},
	{1280, 960, 85, 4, 3, 85900, 148500},
	{1280, 1024, 60, 5, 4, 64000, 108000},
	{1280, 1024, 85, 5, 4, 91100, 157500},
	/* 0x08 bit 7 - 0 */
	{1360, 768, 60, 85, 48, 47700, 85500},
	{1440, 900, 60, 16, 10, 55500, 88750, 1},
	{1440, 900, 60, 16, 10, 65300, 121750},
	{1440, 900, 75, 16, 10, 82300, 156000},
	{1440, 900, 85, 16, 10, 93900, 179500},
	{1400, 1050, 60, 4, 3, 64700, 101000, 1},
	{1400, 1050, 60, 4, 3, 65300, 121750},
	{1400, 1050, 75, 4, 3, 82300, 156000},
	/* 0x09 bit 7 - 0 */
	{1400, 1050, 85, 4, 3, 93900, 179500},
	{1680, 1050, 60, 16, 10, 64700, 119000, 1},
	{1680, 1050, 60, 16, 10, 65300, 146250},
	{1680, 1050, 75, 16, 10, 82300, 187000},
	{1680, 1050, 85, 16, 10, 93900, 214750},
	{1600, 1200, 60, 4, 3, 75000, 162000},
	{1600, 1200, 65, 4, 3, 81300, 175500},
	{1600, 1200, 70, 4, 3, 87500, 189000},
	/* 0x0a bit 7 - 0 */
	{1600, 1200, 75, 4, 3, 93800, 202500},
	{1600, 1200, 85, 4, 3, 106300, 229500},
	{1792, 1344, 60, 4, 3, 83600, 204750},
	{1792, 1344, 75, 4, 3, 106300, 261000},
	{1856, 1392, 60, 4, 3, 86300, 218250},
	{1856, 1392, 75, 4, 3, 112500, 288000},
	{1920, 1200, 60, 16, 10, 74000, 154000, 1},
	{1920, 1200, 60, 16, 10, 74600, 193250},
	/* 0x0b bit 7 - 4 */
	{1920, 1200, 75, 16, 10, 94000, 245250},
	{1920, 1200, 85, 16, 10, 107200, 281250},
	{1920, 1440, 60, 4, 3, 90000, 234000},
	{1920, 1440, 75, 4, 3, 112500, 297000},
};

/* 1 means valid data */
static int detailed_block(const unsigned char *x, int in_extension)
{
	int ha, hbl, va, vbl;
	int refresh, pixclk_khz;
	int i;

	if (x[0] == 0 && x[1] == 0) {
		/* Monitor descriptor block, not detailed timing descriptor. */
		if (x[2] != 0) {
			/* 1.3, 3.10.3 */
			has_valid_descriptor_pad = 0;
		}
		if (x[3] != 0xfd && x[4] != 0x00) {
			/* 1.3, 3.10.3 */
			has_valid_descriptor_pad = 0;
		}

		seen_non_detailed_descriptor = 1;
		if (x[3] <= 0xF) {
			/*
			 * in principle we can decode these, if we know what they are.
			 * 0x0f seems to be common in laptop panels.
			 * 0x0e is used by EPI: http://www.epi-standard.org/
			 */
			return 1;
		}
		switch (x[3]) {
		case 0x10:			
			for (i = 5; i < 18; i++)
				if (x[i] != 0x00)
					has_valid_dummy_block = 0;
			return 1;
		case 0xF7:
			for (i = 0; i < 44; i++) {
				if (x[6 + i / 8] & (1 << (7 - i % 8))) {
					min_vert_freq_hz = min(min_vert_freq_hz, established_timings3[i].refresh);
					max_vert_freq_hz = max(max_vert_freq_hz, established_timings3[i].refresh);
					min_hor_freq_hz = min(min_hor_freq_hz, established_timings3[i].hor_freq_hz);
					max_hor_freq_hz = max(max_hor_freq_hz, established_timings3[i].hor_freq_hz);
					max_pixclk_khz = max(max_pixclk_khz, established_timings3[i].pixclk_khz);
				}
			}
			return 1;
		case 0xF8: {
			int valid_cvt = 1; /* just this block */			
			if (x[5] != 0x01) {
				has_valid_cvt = 0;
				return 0;
			}
			for (i = 0; i < 4; i++)
				valid_cvt &= detailed_cvt_descriptor(x + 6 + (i * 3), (i == 0));
			has_valid_cvt &= valid_cvt;
			return valid_cvt;
		}
		case 0xF9:
			return 1;
		case 0xFA:
			return 1;
		case 0xFB: {
			if (x[10] == 0)
				return 1;
			return 1;
		}
		case 0xFC:
			has_name_descriptor = 1;
			strcpy(model_string, extract_string(x + 5, &has_valid_name_descriptor, 13));
			return 1;
		case 0xFD: {
			int h_max_offset = 0, h_min_offset = 0;
			int v_max_offset = 0, v_min_offset = 0;
			int is_cvt = 0;
			has_range_descriptor = 1;
			/* 
			 * XXX todo: implement feature flags, vtd blocks
			 * XXX check: ranges are well-formed; block termination if no vtd
			 */
			if (claims_one_point_four) {
				if (x[4] & 0x02) {
					v_max_offset = 255;
					if (x[4] & 0x01) {
						v_min_offset = 255;
					}
				}
				if (x[4] & 0x04) {
					h_max_offset = 255;
					if (x[4] & 0x03) {
						h_min_offset = 255;
					}
				}
			} else if (x[4]) {
				has_valid_range_descriptor = 0;
			}

			if (x[5] + v_min_offset > x[6] + v_max_offset)
				has_valid_range_descriptor = 0;
			mon_min_vert_freq_hz = x[5] + v_min_offset;
			mon_max_vert_freq_hz = x[6] + v_max_offset;
			if (x[7] + h_min_offset > x[8] + h_max_offset)
				has_valid_range_descriptor = 0;
			mon_min_hor_freq_hz = (x[7] + h_min_offset) * 1000;
			mon_max_hor_freq_hz = (x[8] + h_max_offset) * 1000;
			if (x[9]) {
				mon_max_pixclk_khz = x[9] * 10000;
			} else {
				if (claims_one_point_four)
					has_valid_max_dotclock = 0;
			}

			if (is_cvt) {
				if (x[12] & 0xfc) {
					int raw_offset = (x[12] & 0xfc) >> 2;
					if (raw_offset >= 40)
						warning_excessive_dotclock_correction = 1;
				}

				if (x[14] & 0x07)
					has_valid_range_descriptor = 0;

#if 0
				switch((x[15] & 0xe0) >> 5) {
				case 0x00: printf("4:3"); break;
				case 0x01: printf("16:9"); break;
				case 0x02: printf("16:10"); break;
				case 0x03: printf("5:4"); break;
				case 0x04: printf("15:9"); break;
				default: printf("(broken)"); break;
				}
#endif
	
				if (x[15] & 0x07)
					has_valid_range_descriptor = 0;

				if (x[16] & 0x0f)
					has_valid_range_descriptor = 0;
			}

			/*
			 * Slightly weird to return a global, but I've never seen any
			 * EDID block wth two range descriptors, so it's harmless.
			 */
			return has_valid_range_descriptor;
		}
		case 0xFE:
			/*
			 * TODO: Two of these in a row, in the third and fourth slots,
			 * seems to be specified by SPWG: http://www.spwg.org/
			 */
			has_ascii_string = 1;
			return 1;
		case 0xFF:
			has_serial_string = 1;
			strcpy(serial_string, extract_string(x + 5, &has_valid_serial_string, 13));
			return 1;
		default:
			return 0;
		}
	}

	if (seen_non_detailed_descriptor && !in_extension) {
		has_valid_descriptor_ordering = 0;
	}

	did_detailed_timing = 1;
	ha = (x[2] + ((x[4] & 0xF0) << 4));
	hbl = (x[3] + ((x[4] & 0x0F) << 8));
	
	va = (x[5] + ((x[7] & 0xF0) << 4));
	vbl = (x[6] + ((x[7] & 0x0F) << 8));

	pixclk_khz = (x[0] + (x[1] << 8)) * 10;
	refresh = (pixclk_khz * 1000) / ((ha + hbl) * (va + vbl));
	min_vert_freq_hz = min(min_vert_freq_hz, refresh);
	max_vert_freq_hz = max(max_vert_freq_hz, refresh);
	min_hor_freq_hz = min(min_hor_freq_hz, (pixclk_khz * 1000) / (ha + hbl));
	max_hor_freq_hz = max(max_hor_freq_hz, (pixclk_khz * 1000) / (ha + hbl));
	max_pixclk_khz = max(max_pixclk_khz, pixclk_khz);
	/* XXX flag decode */

	return 1;
}

static int do_checksum(const unsigned char *x, size_t len)
{
	unsigned char check = x[len - 1];
	unsigned char sum = 0;
	int i;

	for (i = 0; i < len-1; i++)
		sum += x[i];

	if ((unsigned char)(check + sum) != 0) {
		return 0;
	}

	return 1;
}

/* CTA extension */

struct edid_cta_mode {
	const char *name;
	int refresh, hor_freq_hz, pixclk_khz;
};

static struct {
	const char *name;
	int refresh, hor_freq_hz, pixclk_khz;
} edid_hdmi_modes[] = {
	{"3840x2160@30Hz 16:9", 30, 67500, 297000},
	{"3840x2160@25Hz 16:9", 25, 56250, 297000},
	{"3840x2160@24Hz 16:9", 24, 54000, 297000},
	{"4096x2160@24Hz 256:135", 24, 54000, 297000},
};

static void cta_hdmi_block(const unsigned char *x, unsigned int length)
{
	int mask = 0, formats = 0;
	int len_vic, len_3d;
	int b = 0;

	if (length < 6)
		return;

	if (length < 7)
		return;

	if (x[6] * 5 > 340)
		nonconformant_hdmi_vsdb_tmds_rate = 1;

	/* XXX the walk here is really ugly, and needs to be length-checked */
	if (length < 8)
		return;

	if (x[7] & 0x80) {
		b += 2;
		if (x[7] & 0x40) {
			b += 2;
		}
	}

	if (!(x[7] & 0x20))
		return;

	if ((x[8 + b] & 0x60) == 0x20) {
		formats = 1;
	}
	if ((x[8 + b] & 0x60) == 0x40) {
		formats = 1;
		mask = 1;
	}
	switch (x[8 + b] & 0x18) {
	case 0x00: break;
	case 0x08:
		   break;
	case 0x10:
		   break;
	case 0x18:
		   break;
	}
	len_vic = (x[9 + b] & 0xe0) >> 5;
	len_3d = (x[9 + b] & 0x1f) >> 0;
	b += 2;

	if (len_vic) {
		unsigned hfreq = 0;
		unsigned clock_khz = 0;
		int i;

		for (i = 0; i < len_vic; i++) {
			unsigned char vic = x[8 + b + i];
			if (vic && vic <= ARRAY_SIZE(edid_hdmi_modes)) {
				supported_hdmi_vic_codes |= 1 << (vic - 1);
				
				min_vert_freq_hz = min(min_vert_freq_hz, edid_hdmi_modes[vic - 1].refresh);
				max_vert_freq_hz = max(max_vert_freq_hz, edid_hdmi_modes[vic - 1].refresh);
				hfreq = edid_hdmi_modes[vic - 1].hor_freq_hz;
				min_hor_freq_hz = min(min_hor_freq_hz, hfreq);
				max_hor_freq_hz = max(max_hor_freq_hz, hfreq);
				clock_khz = edid_hdmi_modes[vic - 1].pixclk_khz;
				max_pixclk_khz = max(max_pixclk_khz, clock_khz);
			}
		}

		b += len_vic;
	}

	if (len_3d) {
		if (formats) {
			b += 2;
			len_3d -= 2;
		}
		if (mask) {
			b += 2;
			len_3d -= 2;
		}

		/*
		 * list of nibbles:
		 * 2D_VIC_Order_X
		 * 3D_Structure_X
		 * (optionally: 3D_Detail_X and reserved)
		 */
		if (len_3d > 0) {
			int end = b + len_3d;

			while (b < end) {
				switch (x[8 + b] & 0x0f) {
				case 0: break;
				case 6: break;
				case 8:
					if ((x[9 + b] >> 4) == 1) {						
						break;
					}
				default: break;
				}

				if ((x[8 + b] & 0x0f) > 7) {
					/* Optional 3D_Detail_X and reserved */
					b++;
				}
				b++;
			}
		}
	}
}


DEFINE_FIELD("YCbCr quantization", YCbCr_quantization, 7, 7,
	     { 0, "No Data" },
	     { 1, "Selectable (via AVI YQ)" });
DEFINE_FIELD("RGB quantization", RGB_quantization, 6, 6,
	     { 0, "No Data" },
	     { 1, "Selectable (via AVI Q)" });
DEFINE_FIELD("PT scan behaviour", PT_scan, 4, 5,
	     { 0, "No Data" },
	     { 1, "Always Overscannned" },
	     { 2, "Always Underscanned" },
	     { 3, "Support both over- and underscan" });
DEFINE_FIELD("IT scan behaviour", IT_scan, 2, 3,
	     { 0, "IT video formats not supported" },
	     { 1, "Always Overscannned" },
	     { 2, "Always Underscanned" },
	     { 3, "Support both over- and underscan" });
DEFINE_FIELD("CE scan behaviour", CE_scan, 0, 1,
	     { 0, "CE video formats not supported" },
	     { 1, "Always Overscannned" },
	     { 2, "Always Underscanned" },
	     { 3, "Support both over- and underscan" });

static struct field *vcdb_fields[] = {
	&YCbCr_quantization,
	&RGB_quantization,
	&PT_scan,
	&IT_scan,
	&CE_scan,
};


static void cta_vcdb(const unsigned char *x, unsigned int length)
{
	unsigned char d = x[0];

	decode(vcdb_fields, d, "    ");
}

static void cta_block(const unsigned char *x)
{
	static int last_block_was_hdmi_vsdb;
	unsigned int length = x[0] & 0x1f;
	unsigned int oui;

	switch ((x[0] & 0xe0) >> 5) {
	case 0x01:
		break;
	case 0x02:
		break;
	case 0x03:
		/* yes really, endianness lols */
		oui = (x[3] << 16) + (x[2] << 8) + x[1];
		if (oui == 0x000c03) {
			cta_hdmi_block(x + 1, length);
			last_block_was_hdmi_vsdb = 1;
			return;
		}
		if (oui == 0xc45dd8) {
			if (!last_block_was_hdmi_vsdb)
				nonconformant_hf_vsdb_position = 1;
		}
		break;
	case 0x04:
		break;
	case 0x05:
		break;
	case 0x07:
		switch (x[1]) {
		case 0x00:
			cta_vcdb(x + 2, length - 1);
			break;
		case 0x01:
			break;
		case 0x02:
			break;
		case 0x03:
			break;
		case 0x04:
			break;
		case 0x05:
			break;
		case 0x06:
			break;
		case 0x07:
			break;
		case 0x0d:
			break;
		case 0x0e:
			break;
		case 0x0f:
			break;
		case 0x10:
			break;
		case 0x11:
			break;
		case 0x12:
			break;
		case 0x13:
			break;
		case 0x14:
			break;
		case 0x20:
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}
	
	last_block_was_hdmi_vsdb = 0;
}

static int parse_cta(const unsigned char *x)
{
	int ret = 0;
	int version = x[1];
	int offset = x[2];
	const unsigned char *detailed;

	if (version >= 1) do {
		if (version == 1 && x[3] != 0)
			ret = 1;

		if (offset < 4)
			break;

		if (version < 3) {
			if (offset - 4 > 0)
				/* do stuff */ ;
		} else if (version == 3) {
			int i;
			for (i = 4; i < offset; i += (x[i] & 0x1f) + 1) {
				cta_block(x + i);
			}
		}

		for (detailed = x + offset; detailed + 18 < x + 127; detailed += 18)
			if (detailed[0])
				detailed_block(detailed, 1);
	} while (0);

	has_valid_cta_checksum = do_checksum(x, EDID_PAGE_SIZE);
	has_cta861 = 1;
	nonconformant_cta861_640x480 = !has_cta861_vic_1 && !has_640x480p60_est_timing;

	return ret;
}

static int parse_displayid(const unsigned char *x)
{
	int length = x[2];
	/* DisplayID length field is number of following bytes
	 * but checksum is calculated over the entire structure
	 * (excluding DisplayID-in-EDID magic byte)
	 */
	has_valid_displayid_checksum = do_checksum(x+1, length + 5);

	int offset = 5;
	while (length > 0) {
		int tag = x[offset];
		int len = x[offset + 2];

		if (len == 0)
			break;
		switch (tag) {
		case 0:
			break;
		case 1:
			break;
		case 2:
			break;
		case 3:
			break;
		case 4:
			break;
		case 5:
			break;
		case 6:
			break;
		case 7:
			break;
		case 8:
			break;
		case 9:
			break;
		case 0xa:
			break;
		case 0xb:
			break;
		case 0xc:
			break;
		case 0xd:
			break;
		case 0xe:
			break;
		case 0xf:
			break;
		case 0x10:
			break;
		case 0x12:
			break;
		default:
			break;
		}
		length -= len + 3;
		offset += len + 3;
	}
	return 1;
}
/* generic extension code */

static void extension_version(const unsigned char *x)
{
}

static int parse_extension(const unsigned char *x)
{
	int conformant_extension;

	switch(x[0]) {
	case 0x02:
		extension_version(x);
		conformant_extension = parse_cta(x);
		break;
	case 0x10: break;
	case 0x40: break;
	case 0x50: break;
	case 0x60: break;
	case 0x70:
		   extension_version(x);
		   parse_displayid(x);
		   break;
	case 0xF0: break;
	case 0xFF: 
	default:
		   break;
	}

	return conformant_extension;
}

static int edid_lines = 0;

static unsigned char *extract_edid(int fd)
{
	char *ret = NULL;
	char *start, *c;
	unsigned char *out = NULL;
	int state = 0;
	int lines = 0;
	int i;
	int out_index = 0;
	int len, size;

	size = 1 << 10;
	ret = malloc(size);
	len = 0;

	if (ret == NULL)
		return NULL;

	/* Always leave room for the NUL terminator: the buffer is parsed
	   with string functions below */
	for (;;) {
		i = read(fd, ret + len, size - len - 1);
		if (i < 0) {
			free(ret);
			return NULL;
		}
		if (i == 0)
			break;
		len += i;
		if (len == size - 1) {
			char *t;
			size <<= 1;
			t = realloc(ret, size);
			if (t == NULL) {
				free(ret);
				return NULL;
			}
			ret = t;
		}
	}
	ret[len] = '\0';

	/* An EDID is at least 128 bytes long, in any format. This also
	   rejects the empty edid files of disconnected outputs in /sys */
	if (len < 128) {
		free(ret);
		return NULL;
	}

	start = strstr(ret, "EDID_DATA:");
	if (start == NULL)
		start = strstr(ret, "EDID:");
	/* Look for xrandr --verbose output (lines of 16 hex bytes) */
	if (start != NULL) {
		const char indentation1[] = "                ";
		const char indentation2[] = "\t\t";
		/* Used to detect that we've gone past the EDID property */
		const char half_indentation1[] = "        ";
		const char half_indentation2[] = "\t";
		const char *indentation;
		char *s;

		lines = 0;
		for (i = 0;; i++) {
			int j;

			/* Get the next start of the line of EDID hex, assuming spaces for indentation */
			s = strstr(start, indentation = indentation1);
			/* Did we skip the start of another property? */
			if (s && s > strstr(start, half_indentation1))
				break;

			/* If we failed, retry assuming tabs for indentation */
			if (!s) {
				s = strstr(start, indentation = indentation2);
				/* Did we skip the start of another property? */
				if (s && s > strstr(start, half_indentation2))
					break;
			}

			if (!s)
				break;

			lines++;
			start = s + strlen(indentation);

			s = realloc(out, lines * 16);
			if (!s) {
				free(ret);
				free(out);
				return NULL;
			}
			out = (unsigned char *)s;
			c = start;
			for (j = 0; j < 16; j++) {
				char buf[3];
				/* Read a %02x from the log */
				if (!isxdigit(c[0]) || !isxdigit(c[1])) {
					if (j != 0) {
						lines--;
						break;
					}
					free(ret);
					free(out);
					return NULL;
				}
				buf[0] = c[0];
				buf[1] = c[1];
				buf[2] = 0;
				out[out_index++] = strtol(buf, NULL, 16);
				c += 2;
			}
		}

		free(ret);
		edid_lines = lines;
		return out;
	}

	start = strstr(ret, "<BLOCK");
	if (start) {
		/* Parse QuantumData 980 EDID files */
		do {
			start = strstr(start, ">");
			if (start)
				out = realloc(out, out_index + 128);
			if (!start || !out) {
				free(ret);
				free(out);
				return NULL;
			}
			start++;
			for (i = 0; i < 256; i += 2) {
				char buf[3];

				buf[0] = start[i];
				buf[1] = start[i + 1];
				buf[2] = 0;
				out[out_index++] = strtol(buf, NULL, 16);
			}
			start = strstr(start, "<BLOCK");
		} while (start);
		edid_lines = out_index >> 4;
		return out;
	}

	/* Is the EDID provided in hex? */
	for (i = 0; i < 32 && (isspace(ret[i]) || ret[i] == ',' ||
			       tolower(ret[i]) == 'x' || isxdigit(ret[i])); i++);
	if (i == 32) {
		out = malloc(size >> 1);
		if (out == NULL) {
			free(ret);
			return NULL;
		}

		for (c=ret; *c; c++) {
			char buf[3];

			if (!isxdigit(*c) || (*c == '0' && tolower(c[1]) == 'x'))
				continue;

			/* Read a %02x from the log */
			if (!isxdigit(c[0]) || !isxdigit(c[1])) {
				free(ret);
				free(out);
				return NULL;
			}

			buf[0] = c[0];
			buf[1] = c[1];
			buf[2] = 0;

			out[out_index++] = strtol(buf, NULL, 16);
			c++;
		}

		free(ret);
		edid_lines = out_index >> 4;
		return out;
	}

	/* wait, is this a log file? */
	for (i = 0; i < 8; i++) {
		if (!isascii(ret[i])) {
			edid_lines = len / 16;
			return (unsigned char *)ret;
		}
	}

	/* I think it is, let's go scanning */
	if (!(start = strstr(ret, "EDID (in hex):")))
		return (unsigned char *)ret;
	if (!(start = strstr(start, "(II)")))
		return (unsigned char *)ret;

	for (c = start; *c; c++) {
		if (state == 0) {
			char *s;
			/* skip ahead to the : */
			s = strstr(c, ": \t");
			if (!s)
				s = strstr(c, ":     ");
			if (!s)
				break;
			c = s;
			/* and find the first number */
			while (!isxdigit(c[1]))
				c++;
			state = 1;
			lines++;
			s = realloc(out, lines * 16);
			if (!s) {
				free(ret);
				free(out);
				return NULL;
			}
			out = (unsigned char *)s;
		} else if (state == 1) {
			char buf[3];
			/* Read a %02x from the log */
			if (!isxdigit(*c)) {
				state = 0;
				continue;
			}
			buf[0] = c[0];
			buf[1] = c[1];
			buf[2] = 0;
			out[out_index++] = strtol(buf, NULL, 16);
			c++;
		}
	}

	edid_lines = lines;

	free(ret);

	return out;
}


static int edid_from_file(const char *from_file, struct edid_info* info)
{
	int fd;
	unsigned char *edid;
	unsigned char *x;
	time_t the_time;
	struct tm *ptm, ptm_struct;
	int analog, i;

	info->description[0] = '\0';
	
	if (!from_file || !strcmp(from_file, "-")) {
		fd = 0;
	} else if ((fd = open(from_file, O_RDONLY)) == -1) {
		perror(from_file);
		return -1;
	}

	edid = extract_edid(fd);
	if (fd != 0)
		close(fd);
	if (!edid) {
		return -1;
	}

	if (memcmp(edid, "\x00\xFF\xFF\xFF\xFF\xFF\xFF\x00", 8)) {
		free(edid);
		return -1;
	}

	if (edid[0x12] == 1) {
		if (edid[0x13] > 4) {
			edid[0x13] = 4;
		}
		edid_minor = edid[0x13];
		switch (edid[0x13]) {
		case 4:
			claims_one_point_four = 1;
		case 3:
			claims_one_point_three = 1;
		case 2:
			claims_one_point_two = 1;
		default:
			break;
		}
		claims_one_point_oh = 1;
	}
	
	unsigned short model = (unsigned short)(edid[0x0A] + (edid[0x0B] << 8));
	unsigned int serial = (unsigned int)(edid[0x0C] + (edid[0x0D] << 8))
			      + (edid[0x0E] << 16) + (edid[0x0F] << 24);
	(void)model;
	(void)serial;

	has_valid_serial_number = edid[0x0C] || edid[0x0D] || edid[0x0E] || edid[0x0F];
	
	int week = 0;
	int year = 0;

	time(&the_time);
	ptm = localtime_r(&the_time, &ptm_struct);
	if (edid[0x10] < 55 || (edid[0x10] == 0xff && claims_one_point_four)) {
		has_valid_week = 1;
		if (edid[0x11] > 0x0f) {
			if (edid[0x10] == 0xff) {
				has_valid_year = 1;
				week = edid[0x10];
				year = edid[0x11];
#if 0
				printf("Model year %hd\n", edid[0x11] + 1990);
#endif
			} else if (edid[0x11] + 90 <= ptm->tm_year + 1) {
				has_valid_year = 1;
				week = edid[0x10];
				year = edid[0x11] + 1990;
#if 0
				if (edid[0x10])
					printf("Made in week %hd of %hd\n", edid[0x10], edid[0x11] + 1990);
				else
					printf("Made in year %hd\n", edid[0x11] + 1990);
#endif
			}
		}
	}
	
	/* display section */

	if (edid[0x14] & 0x80) {
		int conformance_mask;
		analog = 0;
		if (claims_one_point_four) {
			conformance_mask = 0;
			if ((edid[0x14] & 0x70) == 0x00)
				;
			else if ((edid[0x14] & 0x70) == 0x70)
				nonconformant_digital_display = 1;				

			switch (edid[0x14] & 0x0f) {
			case 0x00:break;
			case 0x01:break;
			case 0x02:break;
			case 0x03:break;
			case 0x04:break;
			case 0x05:break;
			default:
				   nonconformant_digital_display = 1;
			}
		} else if (claims_one_point_two) {
			conformance_mask = 0x7E;			
		} else conformance_mask = 0x7F;
		if (!nonconformant_digital_display)
			nonconformant_digital_display = edid[0x14] & conformance_mask;
	} else {
		analog = 1;
	}

	if (edid[0x18] & 0x04) {
		/*
		 * The sRGB chromaticities are (x, y):
		 * red:   0.640,  0.330
		 * green: 0.300,  0.600
		 * blue:  0.150,  0.060
		 * white: 0.3127, 0.3290
		 */
		static const unsigned char srgb_chromaticity[10] = {
			0xee, 0x91, 0xa3, 0x54, 0x4c, 0x99, 0x26, 0x0f, 0x50, 0x54
		};
		nonconformant_srgb_chromaticity =
			memcmp(edid + 0x19, srgb_chromaticity, sizeof(srgb_chromaticity));
	}
	if (edid[0x18] & 0x02) {
		has_preferred_timing = 1;
	} else if (claims_one_point_four) {
		/* 1.4 always has a preferred timing and this bit means something else. */
		has_preferred_timing = 1;
	}

	for (i = 0; i < 17; i++) {
		if (edid[0x23 + i / 8] & (1 << (7 - i % 8))) {
			min_vert_freq_hz = min(min_vert_freq_hz, established_timings[i].refresh);
			max_vert_freq_hz = max(max_vert_freq_hz, established_timings[i].refresh);
			min_hor_freq_hz = min(min_hor_freq_hz, established_timings[i].hor_freq_hz);
			max_hor_freq_hz = max(max_hor_freq_hz, established_timings[i].hor_freq_hz);
			max_pixclk_khz = max(max_pixclk_khz, established_timings[i].pixclk_khz);
		}
	}
	has_640x480p60_est_timing = edid[0x23] & 0x20;

	/* detailed timings */
	has_valid_detailed_blocks = detailed_block(edid + 0x36, 0);
	if (has_preferred_timing && !did_detailed_timing)
		has_preferred_timing = 0; /* not really accurate... */
	has_valid_detailed_blocks &= detailed_block(edid + 0x48, 0);
	has_valid_detailed_blocks &= detailed_block(edid + 0x5A, 0);
	has_valid_detailed_blocks &= detailed_block(edid + 0x6C, 0);

	has_valid_checksum = do_checksum(edid, EDID_PAGE_SIZE);

	x = edid;
	for (edid_lines /= 8; edid_lines > 1; edid_lines--) {
		x += EDID_PAGE_SIZE;
		nonconformant_extension += parse_extension(x);
	}

	// Fill edid_info struct
	// Manufacturer
	strncpy(info->manufacturer, manufacturer_name(edid + 0x08), sizeof(info->manufacturer));

	// TODO: find out what is the binary number after the %s.%x. I think
	// it's the manufacturer code, but how is it generated ?
	snprintf(info->description, sizeof(info->description), "%s.%x.000000000 (%hd/%hd)",
			info->manufacturer, model, week, year);

	// Model / Serial Number
	strncpy(info->model, model_string, sizeof(info->model));

	int isAcer = strcmp(manufacturer_name(edid + 0x08), "ACR") == 0;
	if (isAcer != 0) {
		/* (Certain?) ACER displays have the serial number scattered in two places:
		 * The first 8 characters is encoded as a hex string immediately after the 000000ff00 flag
		 * the last 4 characters are encoded after this first 8 characters
		 * the middle part is encoded as 4 strings earlier in the EDID block
		 */
		strncpy(info->serial_number, serial_string, 8);
		info->serial_number[8] = '\0';

		char middle[9];
		snprintf(middle, sizeof(middle), "%x%x%x%x%x%x%x%x",
				edid[15], edid[14], edid[13], edid[12],
				edid[11], edid[10], edid[9], edid[8]);
		middle[8] = '\0';

		strncat(info->serial_number, middle, 8);
		strncat(info->serial_number, &serial_string[8], sizeof(serial_string) - 8);
	} else
		strncpy(info->serial_number, serial_string, sizeof(info->serial_number));

	if (analog)
		snprintf(info->type, sizeof(info->type), "Analog display");
	else
		snprintf(info->type, sizeof(info->type), "Digital display");
	free(edid);

	return 0;
}


int get_edid_info(const char *filename, struct edid_info* info)
{
	return edid_from_file(filename, info);
}


/*
 * Notes on panel extensions: (TODO, implement me in the code)
 *
 * EPI: http://www.epi-standard.org/fileadmin/spec/EPI_Specification1.0.pdf
 * at offset 0x6c (fourth detailed block): (all other bits reserved)
 * 0x6c: 00 00 00 0e 00
 * 0x71: bit 6-5: data color mapping (00 conventional/fpdi/vesa, 01 openldi)
 *       bit 4-3: pixels per clock (00 1, 01 2, 10 4, 11 reserved)
 *       bit 2-0: bits per pixel (000 18, 001 24, 010 30, else reserved)
 * 0x72: bit 5: FPSCLK polarity (0 normal 1 inverted)
 *       bit 4: DE polarity (0 high active 1 low active)
 *       bit 3-0: interface (0000 LVDS TFT
 *                           0001 mono STN 4/8bit
 *                           0010 color STN 8/16 bit
 *                           0011 18 bit tft
 *                           0100 24 bit tft
 *                           0101 tmds
 *                           else reserved)
 * 0x73: bit 1: horizontal display mode (0 normal 1 right/left reverse)
 *       bit 0: vertical display mode (0 normal 1 up/down reverse)
 * 0x74: bit 7-4: total poweroff seq delay (0000 vga controller default
 *                                          else time in 10ms (10ms to 150ms))
 *       bit 3-0: total poweron seq delay (as above)
 * 0x75: contrast power on/off seq delay, same as 0x74
 * 0x76: bit 7: backlight control enable (1 means this field is valid)
 *       bit 6: backlight enabled at boot (0 on 1 off)
 *       bit 5-0: backlight brightness control steps (0..63)
 * 0x77: bit 7: contrast control, same bit pattern as 0x76 except bit 6 resvd
 * 0x78 - 0x7c: reserved
 * 0x7d: bit 7-4: EPI descriptor major version (1)
 *       bit 3-0: EPI descriptor minor version (0)
 *
 * ----
 *
 * SPWG: http://www.spwg.org/spwg_spec_version3.8_3-14-2007.pdf
 *
 * Since these are "dummy" blocks, terminate with 0a 20 20 20 ... as usual
 *
 * detailed descriptor 3:
 * 0x5a - 0x5e: 00 00 00 fe 00
 * 0x5f - 0x63: PC maker part number
 * 0x64: LCD supplier revision #
 * 0x65 - 0x6b: manufacturer part number
 *
 * detailed descriptor 4:
 * 0x6c - 0x70: 00 00 00 fe 00
 * 0x71 - 0x78: smbus nits values (whut)
 * 0x79: number of lvds channels (1 or 2)
 * 0x7A: panel self test (1 if present)
 * and then dummy terminator
 *
 * SPWG also says something strange about the LSB of detailed descriptor 1:
 * "LSB is set to "1" if panel is DE-timing only. H/V can be ignored."
 */
