/*
 * Public interface of the ThinkPad backlight driver (/dev/misc/backlight).
 * Distributed under the terms of the MIT license.
 */
#ifndef THINKPAD_BACKLIGHT_H
#define THINKPAD_BACKLIGHT_H

#include <Drivers.h>

#define BACKLIGHT_DEVICE_NAME	"misc/backlight"

enum {
	BACKLIGHT_GET_INFO = B_DEVICE_OP_CODES_END + 1,	/* backlight_info* */
	BACKLIGHT_SET_LEVEL,							/* uint32* (raw level) */
	BACKLIGHT_SET_PERCENT,							/* uint32* (0-100) */
};

typedef struct backlight_info {
	uint32	min_level;	/* lowest level the driver accepts (never fully off) */
	uint32	max_level;	/* PWM period */
	uint32	level;		/* current duty cycle */
	uint32	percent;	/* current level as a percentage of max_level */
	uint32	enabled;	/* PWM enable bit as programmed by the firmware */
} backlight_info;

#endif	/* THINKPAD_BACKLIGHT_H */
