#pragma once

#include "common.hpp"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * unfself — extract the plaintext ELF from a FAKE-signed SELF (fself), without
 * decryption. Port of SocraticBliss's UnFSelf.py. A fake-signed self stores its
 * segments in plaintext, so we just place each SELF entry's data at the matching
 * ELF program header (matched by file size, like the reference) and copy the ELF
 * header + program headers verbatim.
 *
 * Only fake-signed selfs (extended info ptype == PT_FAKE) are handled — a real
 * (encrypted) self must go through self_decrypt_file instead.
 *
 * Returns 1 on success, 0 if the input is not a fake-signed self, <0 on error.
 */
int self_unfself_file(const char* self_path, const char* elf_path);
int self_unfself_buffer(const void* self_data, size_t self_size, uint8_t** out_elf, size_t* out_elf_size);

#ifdef __cplusplus
}
#endif
