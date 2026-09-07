#pragma once

#include "common.hpp"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * make_fself — wrap a plaintext ELF/PRX into a FAKE-signed SELF (fself).
 * Port of flatz's make_fself3.py. The inverse of unfself: builds a fresh SELF
 * header + entry table + (zeroed) meta blocks + plaintext segments so the
 * result mounts on a jailbroken console without real signing keys.
 *
 * Segments are stored unencrypted/unsigned with empty digests (fake self); only
 * PT_LOAD / PT_SCE_RELRO / PT_SCE_DYNLIBDATA / PT_SCE_COMMENT get entries, and
 * the PT_SCE_VERSION body is appended verbatim after the last segment.
 */

struct makefself_opts {
  uint64_t paid;        /* program authentication id (default 0x3100000000000002) */
  uint64_t ptype;       /* program type            (default SELF_PTYPE_FAKE = 1)   */
  uint64_t app_version; /* default 0 */
  uint64_t fw_version;  /* default 0 */
  const uint8_t* auth_info; /* 0x88-byte auth info, or NULL (default) */
};

/* Fill opts with make_fself's defaults. */
void makefself_opts_default(struct makefself_opts* opts);

/* Returns 1 on success, 0 if the input is not a supported ELF, <0 on error. */
int self_make_fself_file(const char* elf_path, const char* self_path, const struct makefself_opts* opts);
int self_make_fself_buffer(const void* elf_data, size_t elf_size, const struct makefself_opts* opts, uint8_t** out_self, size_t* out_self_size);

#ifdef __cplusplus
}
#endif
