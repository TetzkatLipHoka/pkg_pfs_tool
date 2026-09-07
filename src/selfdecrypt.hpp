#pragma once

#include "common.hpp"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * PS4 SELF/SPRX decryption (retail x86-64). Ported from flatz's self_tool4.py,
 * built on the SELF/ELF parsing in self.hpp and the crypto in crypto.hpp.
 * Root keys are loaded from the config file's [self_keys] section (see keys.h
 * g_self_root_keys) — nothing is hardcoded.
 *
 * The metadata key is selected by decrypting the metadata with each candidate
 * key and verifying the RSA signature (no 7-zero-bytes heuristic, no brute-force
 * over flags): the key generation whose RSA public key validates the signature
 * is the correct one. This addresses the original tool's key-bruteforce TODOs.
 */

/* Decrypt a SELF/SPRX file to a plaintext ELF file. Returns 1 on success. */
int self_decrypt_file(const char* self_path, const char* elf_path);

/* Decrypt an in-memory SELF image to a freshly malloc'd plaintext ELF buffer.
   On success returns 1 and sets *out_elf / *out_elf_size (caller frees). */
int self_decrypt_buffer(const void* self_data, size_t self_size, uint8_t** out_elf, size_t* out_elf_size);

#ifdef __cplusplus
}
#endif
