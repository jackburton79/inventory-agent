/*
 * backlight - command line tool for /dev/misc/backlight
 *
 *   backlight            show the current brightness
 *   backlight 60         set 60%
 *   backlight +10 / -10  change by 10 points
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/ioctl.h>

#include "thinkpad_backlight.h"

int
main(int argc, char** argv)
{
	int fd = open("/dev/" BACKLIGHT_DEVICE_NAME, O_RDWR);
	if (fd < 0) {
		perror("backlight: cannot open /dev/" BACKLIGHT_DEVICE_NAME);
		return 1;
	}

	backlight_info info;
	if (ioctl(fd, BACKLIGHT_GET_INFO, &info, sizeof(info)) != 0) {
		perror("backlight: GET_INFO");
		return 1;
	}

	if (argc < 2) {
		printf("%u%% (level %u of %u, minimum %u)\n", (unsigned)info.percent,
			(unsigned)info.level, (unsigned)info.max_level,
			(unsigned)info.min_level);
		return 0;
	}

	int value = atoi(argv[1]);
	if (argv[1][0] == '+' || argv[1][0] == '-')
		value += (int)info.percent;
	if (value < 0)
		value = 0;
	if (value > 100)
		value = 100;

	uint32 percent = (uint32)value;
	if (ioctl(fd, BACKLIGHT_SET_PERCENT, &percent, sizeof(percent)) != 0) {
		perror("backlight: SET_PERCENT");
		return 1;
	}
	return 0;
}
