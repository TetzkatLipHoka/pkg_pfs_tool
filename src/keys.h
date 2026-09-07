#pragma once

#include "crypto.hpp"
#include "keymgr.h"

#ifdef __cplusplus
extern "C" {
#endif

extern struct rsa_keyset g_rsa_keyset_pkg_entry_key_3;

#if defined(ENABLE_EKC_KEYGEN)
extern struct rsa_keyset g_rsa_keyset_pkg_debug_ekpfs_key;
extern struct rsa_keyset g_rsa_keyset_pkg_retail_ekpfs_key_0;
extern struct rsa_keyset g_rsa_keyset_pkg_retail_ekpfs_key_1;
#endif

extern struct rsa_keyset g_rsa_keyset_pkg_fake_ekpfs_key;

extern struct rsa_keyset g_rsa_keyset_pfs_sig_key;

extern const uint8_t g_debug_pfs_zero_crypt_seed[0x10];

#if defined(ENABLE_EKC_KEYGEN)
extern uint8_t* g_ekpfs_obf_key_1;
extern uint8_t* g_ekpfs_obf_key_2;
extern uint8_t* g_ekpfs_obf_key_3;
extern uint8_t* g_ekpfs_obf_key_4;
extern uint8_t* g_ekpfs_obf_key_5;
extern uint8_t* g_ekpfs_obf_key_6;
extern uint8_t* g_ekpfs_obf_key_7;
extern uint8_t* g_ekpfs_obf_key_8;
extern uint8_t* g_ekpfs_obf_key_9;
extern uint8_t* g_ekpfs_obf_key_10;
extern uint8_t* g_ekpfs_obf_key_11;
extern uint8_t* g_ekpfs_obf_key_12;
extern uint8_t* g_ekpfs_obf_key_13;
extern uint8_t* g_ekpfs_obf_key_14;
extern uint8_t* g_ekpfs_obf_key_15;
extern uint8_t* g_ekpfs_obf_key_16;
extern uint8_t* g_ekpfs_obf_key_17;
extern uint8_t* g_ekpfs_obf_key_18;
extern uint8_t* g_ekpfs_obf_key_19;

extern uint8_t* g_gdgp_ekc_key_0;
extern uint8_t* g_gdgp_ekc_key_1;
extern uint8_t* g_gdgp_ekc_key_2;

extern uint8_t* g_gdgp_content_key_obf_key;
extern uint8_t* g_ac_content_key;
#endif

#if defined(ENABLE_SD_KEYGEN)
extern uint8_t* g_idps;
extern uint8_t* g_open_psid;

extern uint8_t* g_sealed_key_enc_key_1;
extern uint8_t* g_sealed_key_enc_key_2;
extern uint8_t* g_sealed_key_enc_key_3;
extern uint8_t* g_sealed_key_enc_key_4;
extern uint8_t* g_sealed_key_enc_key_5;
extern uint8_t* g_sealed_key_enc_key_6;
extern uint8_t* g_sealed_key_enc_key_7;
extern uint8_t* g_sealed_key_enc_key_8;
extern uint8_t* g_sealed_key_enc_key_9;
extern uint8_t* g_sealed_key_enc_key_10;

extern uint8_t* g_sealed_key_sign_key_1;
extern uint8_t* g_sealed_key_sign_key_2;
extern uint8_t* g_sealed_key_sign_key_3;
extern uint8_t* g_sealed_key_sign_key_4;
extern uint8_t* g_sealed_key_sign_key_5;
extern uint8_t* g_sealed_key_sign_key_6;
extern uint8_t* g_sealed_key_sign_key_7;
extern uint8_t* g_sealed_key_sign_key_8;
extern uint8_t* g_sealed_key_sign_key_9;
extern uint8_t* g_sealed_key_sign_key_10;

extern uint8_t* g_sd_auth_code_key;

extern uint8_t* g_sd_hdr_data_key;
extern uint8_t* g_sd_hdr_sig_key;

extern uint8_t* g_open_psid_sig_key;

extern uint8_t* g_sd_content_key_1;
extern uint8_t* g_sd_content_key_2;
extern uint8_t* g_sd_content_key_3;
extern uint8_t* g_sd_content_key_4;
extern uint8_t* g_sd_content_key_5;
extern uint8_t* g_sd_content_key_6;
extern uint8_t* g_sd_content_key_7;
extern uint8_t* g_sd_content_key_8;
extern uint8_t* g_sd_content_key_9;
#endif

int check_rsa_key_filled(const struct rsa_keyset* key, int is_private);

/* SELF/SPRX decryption root keys (retail x86-64), loaded from config [self_keys].
   Four key generations; each has a list of AES-128 key/IV candidates and one RSA
   public key. The correct (generation, index) is found by decrypting the metadata
   and verifying the RSA signature (no brute-force heuristic). */
#define SELF_ROOT_KEY_TYPE_COUNT 4
#define SELF_ROOT_KEY_MAX_KEYS   24
#define SELF_ROOT_AES_KEY_SIZE   16

struct self_root_keyset {
  uint32_t key_type;                                       /* 0x00, 0x01, 0x02, 0x100 */
  size_t key_count;
  uint8_t aes_key[SELF_ROOT_KEY_MAX_KEYS][SELF_ROOT_AES_KEY_SIZE];
  uint8_t aes_iv[SELF_ROOT_KEY_MAX_KEYS][SELF_ROOT_AES_KEY_SIZE];
  struct rsa_keyset rsa;                                   /* n from config, e = 0x10001 */
};

extern struct self_root_keyset g_self_root_keys[SELF_ROOT_KEY_TYPE_COUNT];

/* Maps key generation index 0..3 to its on-chip key_type id. */
extern const uint32_t g_self_root_key_types[SELF_ROOT_KEY_TYPE_COUNT];

#ifdef __cplusplus
}
#endif
