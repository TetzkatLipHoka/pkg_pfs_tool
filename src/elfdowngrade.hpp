#pragma once

#include "common.hpp"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * PS4 ELF SDK downgrader (stages 1-3 of flatz's Downgrade_ELF2.py) — the
 * SELF/PRX equivalent of the param.sfo sdk_ver backport. Operates on an already
 * DECRYPTED plaintext ELF, in place:
 *   1) proc/module param structure sdk_version (PT_SCE_PROCPARAM / _MODULE_PARAM)
 *   2) PT_SCE_VERSION library-list per-entry sdk version (big-endian)
 *   3) zero the ELF section-header offset/count (stops orbis-bin complaints)
 * Memory-hole removal (needed only for target < fw 6.00) is NOT implemented.
 *
 * target_sdk is the packed u32, e.g. strtoul("05050001", NULL, 16) = 0x05050001.
 * Every field is only lowered (old > new), never raised.
 *
 * Returns 1 if the file was patched (and rewritten), 0 if nothing changed or the
 * file is not a downgradable SCE ELF, <0 on error.
 */
int elf_downgrade_file(const char* path, uint32_t target_sdk);

#ifdef __cplusplus
}
#endif
