/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "id128-util.h"

/* Reading of EFI variables through efivarfs, after src/basic/efivars.c and src/shared/efi-loader.c
 * of systemd. */

#define EFI_VENDOR_LOADER_STR  "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
#define EFI_VENDOR_SYSTEMD_STR "8cf2644b-4b0b-428f-9387-6d876050dc67"

#define EFI_VENDOR_VARIABLE_STR(vendor, name) name "-" vendor
#define EFI_LOADER_VARIABLE_STR(name) EFI_VENDOR_VARIABLE_STR(EFI_VENDOR_LOADER_STR, name)
#define EFI_SYSTEMD_VARIABLE_STR(name) EFI_VENDOR_VARIABLE_STR(EFI_VENDOR_SYSTEMD_STR, name)

bool is_efi_boot(void);

int efi_get_variable(const char *variable, uint32_t *ret_attribute, void **ret_value, size_t *ret_size);
int efi_get_variable_string(const char *variable, char **ret);
int efi_get_variable_id128(const char *variable, id128_t *ret);

/* The partition UUID of the ESP or XBOOTLDR partition the boot loader was started from */
int efi_loader_get_device_part_uuid(id128_t *ret);

/* Converts an EFI_GUID as it is stored in EFI and on disk (e.g. in a GPT partition entry) into an id128 */
id128_t efi_guid_to_id128(const void *guid);
