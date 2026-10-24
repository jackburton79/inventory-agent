/*
 * Backlight driver for the ThinkPad T450s (Intel HD Graphics 5500, Broadwell).
 *
 * The panel brightness is controlled by the PWM unit of the PCH (LPT-LP):
 *   BLC_PWM_PCH_CTL1 (0xC8250)  bit 31 enable, bit 29 polarity
 *   BLC_PWM_PCH_CTL2 (0xC8254)  bits 31:16 period, bits 15:0 duty cycle
 * Same layout as Linux i915 (lpt_*_backlight) and Haiku's intel_extreme.h.
 *
 * Only the duty cycle is written; the firmware's period, polarity and
 * enable bit are left untouched. The device is not published if the PWM
 * period is zero (backlight not set up by the firmware).
 *
 * Distributed under the terms of the MIT license.
 */

#include <Drivers.h>
#include <KernelExport.h>
#include <OS.h>
#include <PCI.h>

#include <stdbool.h>
#include <string.h>

#include "thinkpad_backlight.h"


#define PCI_VENDOR_INTEL		0x8086
#define MMIO_MAP_SIZE			0x100000	/* covers 0xC8250 */

#define BLC_PWM_PCH_CTL1		0xC8250
#define BLC_PWM_PCH_CTL2		0xC8254
#define   PWM_ENABLE			(1U << 31)
#define   PWM_PERIOD_SHIFT		16
#define   PWM_DUTY_MASK			0xFFFFU

#define MIN_PERCENT				5

/* Broadwell GT2/GT3 mobile parts (HD 5500 on the T450s is 0x1616) */
static const uint16 kSupportedDevices[] = {
	0x1602, 0x1606, 0x160B, 0x160E, 0x1612, 0x1616, 0x161E,
	0x1622, 0x1626, 0x162B, 0x162E,
};

static const char* kDeviceNames[] = { BACKLIGHT_DEVICE_NAME, NULL };

int32 api_version = B_CUR_DRIVER_API_VERSION;

static pci_module_info* sPCI;
static area_id sArea = -1;
static volatile uint8* sRegisters;
static sem_id sLock = -1;
static int32 sOpenCount;


static inline uint32
read32(uint32 offset)
{
	return *(volatile uint32*)(sRegisters + offset);
}


static inline void
write32(uint32 offset, uint32 value)
{
	*(volatile uint32*)(sRegisters + offset) = value;
}


static bool
is_supported(const pci_info* info)
{
	if (info->vendor_id != PCI_VENDOR_INTEL || info->class_base != PCI_display)
		return false;
	for (size_t i = 0; i < sizeof(kSupportedDevices) / sizeof(kSupportedDevices[0]);
			i++) {
		if (info->device_id == kSupportedDevices[i])
			return true;
	}
	return false;
}


static bool
find_device_info(pci_info* info)
{
	for (int32 i = 0; sPCI->get_nth_pci_info(i, info) == B_OK; i++) {
		if (is_supported(info))
			return true;
	}
	return false;
}


static void
get_info(backlight_info* info)
{
	uint32 period = read32(BLC_PWM_PCH_CTL2) >> PWM_PERIOD_SHIFT;
	uint32 duty = read32(BLC_PWM_PCH_CTL2) & PWM_DUTY_MASK;

	info->max_level = period;
	info->min_level = (period * MIN_PERCENT + 99) / 100;
	if (info->min_level < 1)
		info->min_level = 1;
	info->level = duty;
	info->percent = (duty * 100 + period / 2) / period;
	info->enabled = (read32(BLC_PWM_PCH_CTL1) & PWM_ENABLE) != 0;
}


static status_t
set_level(uint32 level)
{
	backlight_info info;
	get_info(&info);

	if (level < info.min_level)
		level = info.min_level;
	if (level > info.max_level)
		level = info.max_level;

	uint32 value = read32(BLC_PWM_PCH_CTL2) & ~PWM_DUTY_MASK;
	write32(BLC_PWM_PCH_CTL2, value | level);
	return B_OK;
}


//	#pragma mark - device hooks


static status_t
backlight_open(const char* name, uint32 flags, void** cookie)
{
	(void)name;
	(void)flags;
	atomic_add(&sOpenCount, 1);
	*cookie = NULL;
	return B_OK;
}


static status_t
backlight_close(void* cookie)
{
	(void)cookie;
	return B_OK;
}


static status_t
backlight_free(void* cookie)
{
	(void)cookie;
	atomic_add(&sOpenCount, -1);
	return B_OK;
}


static status_t
backlight_control(void* cookie, uint32 op, void* buffer, size_t length)
{
	(void)cookie;
	status_t status;

	switch (op) {
		case BACKLIGHT_GET_INFO:
		{
			backlight_info info;
			if (length < sizeof(info))
				return B_BAD_VALUE;
			if (acquire_sem(sLock) != B_OK)
				return B_ERROR;
			get_info(&info);
			release_sem(sLock);
			return user_memcpy(buffer, &info, sizeof(info));
		}

		case BACKLIGHT_SET_LEVEL:
		case BACKLIGHT_SET_PERCENT:
		{
			uint32 value;
			if (length < sizeof(value))
				return B_BAD_VALUE;
			if (user_memcpy(&value, buffer, sizeof(value)) != B_OK)
				return B_BAD_ADDRESS;
			if (acquire_sem(sLock) != B_OK)
				return B_ERROR;
			if (op == BACKLIGHT_SET_PERCENT) {
				if (value > 100)
					value = 100;
				value = ((read32(BLC_PWM_PCH_CTL2) >> PWM_PERIOD_SHIFT) * value
					+ 50) / 100;
			}
			status = set_level(value);
			release_sem(sLock);
			return status;
		}
	}

	return B_DEV_INVALID_IOCTL;
}


static status_t
backlight_read(void* cookie, off_t position, void* buffer, size_t* length)
{
	(void)cookie; (void)position; (void)buffer;
	*length = 0;
	return B_OK;
}


static status_t
backlight_write(void* cookie, off_t position, const void* buffer, size_t* length)
{
	(void)cookie; (void)position; (void)buffer; (void)length;
	return B_NOT_ALLOWED;
}


static device_hooks sDeviceHooks = {
	backlight_open,
	backlight_close,
	backlight_free,
	backlight_control,
	backlight_read,
	backlight_write,
	NULL, NULL, NULL, NULL
};


//	#pragma mark - driver entry points


status_t
init_hardware(void)
{
	pci_module_info* pci;
	pci_info info;
	status_t status = get_module(B_PCI_MODULE_NAME, (module_info**)&pci);
	if (status != B_OK)
		return status;

	sPCI = pci;
	status = find_device_info(&info) ? B_OK : B_ERROR;
	sPCI = NULL;
	put_module(B_PCI_MODULE_NAME);
	return status;
}


status_t
init_driver(void)
{
	pci_info info;
	status_t status = get_module(B_PCI_MODULE_NAME, (module_info**)&sPCI);
	if (status != B_OK)
		return status;

	if (!find_device_info(&info)) {
		status = B_ERROR;
		goto err;
	}

	{
		phys_addr_t base = info.u.h0.base_registers[0];
		if ((info.u.h0.base_register_flags[0] & PCI_address_type)
				== PCI_address_type_64) {
			base |= (phys_addr_t)info.u.h0.base_registers[1] << 32;
		}

		sArea = map_physical_memory("thinkpad backlight mmio", base,
			MMIO_MAP_SIZE, B_ANY_KERNEL_ADDRESS | B_MTR_UC,
			B_KERNEL_READ_AREA | B_KERNEL_WRITE_AREA, (void**)&sRegisters);
		if (sArea < 0) {
			status = sArea;
			goto err;
		}
	}

	if ((read32(BLC_PWM_PCH_CTL2) >> PWM_PERIOD_SHIFT) == 0) {
		dprintf("thinkpad_backlight: PWM period is 0, backlight not "
			"controlled by the PCH\n");
		status = B_NOT_SUPPORTED;
		goto err_area;
	}

	sLock = create_sem(1, "thinkpad backlight lock");
	if (sLock < 0) {
		status = sLock;
		goto err_area;
	}
	return B_OK;

err_area:
	delete_area(sArea);
	sArea = -1;
err:
	put_module(B_PCI_MODULE_NAME);
	sPCI = NULL;
	return status;
}


void
uninit_driver(void)
{
	delete_sem(sLock);
	delete_area(sArea);
	sArea = -1;
	sRegisters = NULL;
	put_module(B_PCI_MODULE_NAME);
	sPCI = NULL;
}


const char**
publish_devices(void)
{
	return kDeviceNames;
}


device_hooks*
find_device(const char* name)
{
	if (strcmp(name, BACKLIGHT_DEVICE_NAME) == 0)
		return &sDeviceHooks;
	return NULL;
}
