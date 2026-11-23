/*
 * Sounds.h
 */

#ifndef __SOUNDS_H
#define __SOUNDS_H

#include "ItemsList.h"

#include <string>

struct sound_info {
	int card = -1;			// ALSA card index
	std::string id;			// ALSA card id (e.g. "PCH")
	std::string driver;		// ALSA driver (e.g. "HDA-Intel")
	std::string name;
	std::string description;
	std::string manufacturer;
};

// The sound cards known to ALSA, as listed by /proc/asound/cards
class SoundCards : public ItemsList<sound_info> {
public:
	SoundCards();
};

#endif
