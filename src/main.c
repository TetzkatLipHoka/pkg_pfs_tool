#if defined(_MSC_VER)
#  include "getopt.h" /* bundled OpenBSD getopt (src/getopt.c) */
#else
#  include <getopt.h>
#endif

/* has_arg values for struct option; same on all platforms */
#define ARG_NULL no_argument
#define ARG_NONE no_argument
#define ARG_REQ  required_argument
#define ARG_OPT  optional_argument

#include "pkg.h"
#include "self.hpp"
#include "selfdecrypt.hpp"
#include "elfdowngrade.hpp"
#include "unfself.hpp"
#include "makefself.hpp"
#include "gp4.h"
#include "sfo.hpp"
#include "playgo.hpp"
#include "crypto.hpp"
#include "keys.h"
#include "mapped_file.h"
#include "util.h"
#include "keymgr.h"

#include <dirent.h>
#include <utarray.h>
#include <utstring.h>

static char* s_input_file_path = NULL;
#if defined(ENABLE_REPACK_SUPPORT)
static char* s_plaintext_elf_directory = NULL;
#endif
static char* s_output_file_path = NULL;
static char s_output_directory[PATH_MAX];

static int s_cmd_info = 0;
static int s_cmd_list = 0;
static int s_cmd_unpack = 0;
#if defined(ENABLE_REPACK_SUPPORT)
static int s_cmd_repack = 0;
#endif
static int s_cmd_decrypt_self = 0;
static int s_decrypt_elfs = 0;
static int s_opt_decrypt_elfs_flag = 0;
static int s_downgrade = 0;
static int s_opt_downgrade_flag = 0;
static int s_rewrap_fself = 0;
static int s_opt_rewrap_fself_flag = 0;
static int s_cmd_downgrade_elf = 0;
static int s_cmd_unfself = 0;
static int s_cmd_make_fself = 0;

/* make_fself (--make-fself) options; unset ones fall back to makefself defaults. */
static uint64_t s_mkfs_paid = 0;        static int s_mkfs_paid_set = 0;
static uint64_t s_mkfs_ptype = 0;       static int s_mkfs_ptype_set = 0;
static uint64_t s_mkfs_app_version = 0; static int s_mkfs_app_version_set = 0;
static uint64_t s_mkfs_fw_version = 0;  static int s_mkfs_fw_version_set = 0;
static uint8_t* s_mkfs_auth_info = NULL;
static int s_opt_mkfs_paid_flag = 0;
static int s_opt_mkfs_ptype_flag = 0;
static int s_opt_mkfs_app_version_flag = 0;
static int s_opt_mkfs_fw_version_flag = 0;
static int s_opt_mkfs_auth_info_flag = 0;

static int s_opt_key_content_id_flag = 0;
#if defined(ENABLE_REPACK_SUPPORT)
static int s_opt_content_id_flag = 0;
#endif
static int s_opt_passcode_flag = 0;
#ifdef ENABLE_SD_KEYGEN
static int s_opt_sealed_key_file_flag = 0;
#endif
static int s_opt_encdec_tweak_key_flag = 0;
static int s_opt_encdec_data_key_flag = 0;
static int s_opt_sign_key_flag = 0;
static int s_opt_sc0_key_flag = 0;
static int s_opt_use_meta_data_flag = 0;
static int s_opt_dump_meta_data_flag = 0;
static int s_opt_pfs_image_data_file_flag = 0;
static int s_opt_gp4_file_flag = 0;
static int s_opt_unpack_outer_pfs_flag = 0;
static int s_opt_unpack_inner_pfs_flag = 0;
static int s_opt_unpack_sc_entries_flag = 0;
static int s_opt_unpack_extra_sc_entries_flag = 0;
static int s_opt_use_splitted_files_flag = 0;
static int s_opt_no_unpack_flag = 0;
static int s_opt_no_signature_check_flag = 0;
static int s_opt_no_icv_check_flag = 0;
#if defined(ENABLE_REPACK_SUPPORT)
static int s_opt_no_hash_recalc_flag = 0;
static int s_opt_no_elf_repack_flag = 0;
#endif
static int s_opt_dump_sfo_flag = 0;
static int s_opt_backport_flag = 0;
static int s_opt_sdk_version_flag = 0;
static int s_opt_dump_playgo_flag = 0;
static int s_opt_dump_final_keys_flag = 0;
#if defined(ENABLE_SD_KEYGEN)
static int s_opt_dump_sd_info_flag = 0;
#endif
static int s_opt_use_random_passcode_flag = 0;
static int s_opt_all_compressed_flag = 0;

static char* s_key_content_id = NULL;
#if defined(ENABLE_REPACK_SUPPORT)
static char* s_content_id = NULL;
#endif
static char* s_passcode = NULL;
#ifdef ENABLE_SD_KEYGEN
static char* s_sealed_key_file = NULL;
#endif
static uint8_t* s_encdec_tweak_key = NULL;
static uint8_t* s_encdec_data_key = NULL;
static uint8_t* s_sign_key = NULL;
static uint8_t* s_sc0_key = NULL;
static char* s_meta_data_in_file = NULL;
static char* s_meta_data_out_file = NULL;
static char* s_pfs_image_data_file = NULL;
static char* s_gp4_file = NULL;
static int s_unpack_outer_pfs = 0;
static int s_unpack_inner_pfs = 0;
static int s_unpack_sc_entries = 0;
static int s_unpack_extra_sc_entries = 0;
static int s_use_splitted_files = 0;
static int s_no_unpack = 0;
static int s_no_signature_check = -1;
static int s_no_icv_check = -1;
#if defined(ENABLE_REPACK_SUPPORT)
static int s_no_hash_recalc = 0;
static int s_no_elf_repack = 0;
#endif
static int s_dump_sfo = 0;
static int s_backport = 0;
static char* s_sdk_version = NULL;
static int s_dump_playgo = 0;
static int s_dump_final_keys = 0;
#if defined(ENABLE_SD_KEYGEN)
static int s_dump_sd_info = 0;
#endif
static int s_use_random_passcode = 0;
static int s_all_compressed = 0;
static UT_array* s_file_paths = NULL;

static uint8_t s_pkg_magic[] = { '\x7F', 'C', 'N', 'T' };

static struct pkg* s_pkg = NULL;
static struct pfs* s_pfs = NULL;

static void show_version(void);
static void show_usage(char* argv[]);

static void cleanup(void);

struct pfs_io_context {
  struct file_map* map;
  uint64_t offset;
};

#if defined(ENABLE_REPACK_SUPPORT)
  struct pfs_repack_process_dir_cb_args {
    struct file_map* map;
  };

  struct pfs_repack_dump_indirect_block_cb_args {
    struct file_map* map;
  };

  struct pkg_repack_self_cb_args {
    struct pkg* pkg;
    const char* elf_directory;
  };
#endif

struct pkg_unpack_sc_entries_cb_args {
  const char* output_directory;
  pfs_unpack_pre_cb pre_cb;
  void* pre_cb_arg;
};

static int pfs_get_size_cb(void* arg, uint64_t* size);
static int pfs_get_outer_location_cb(void* arg, uint64_t offset, uint64_t* outer_offset);
static int pfs_get_offset_size_cb(void* arg, uint64_t data_size, uint64_t* real_offset, uint64_t* size_to_read, int* compressed);
static int pfs_seek_cb(void* arg, uint64_t offset);
static int pfs_read_cb(void* arg, void* data, uint64_t data_size);
static int pfs_write_cb(void* arg, void* data, uint64_t data_size);
static int pfs_can_seek_cb(void* arg, uint64_t offset);
static int pfs_can_read_cb(void* arg, uint64_t data_size);
static int pfs_can_write_cb(void* arg, uint64_t data_size);

typedef int (*cmd_handler_t)(void* arg);

#if defined(ENABLE_REPACK_SUPPORT)
#  define RIGHT_SPRX_PATH "/sce_sys/about/right.sprx"

  int test_fself(void) {
    struct file_map* self_map = NULL;
    struct file_map* elf_map = NULL;
    uint8_t* new_self_data = NULL;
    struct self* new_self = NULL;
    struct self* self = NULL;
    struct elf* elf = NULL;
    int status = 0;

    self_map = map_file("eboot.bin");
    if (!self_map)
      goto error;

    elf_map = map_file("eboot.bin.elf");
    if (!elf_map)
      goto error;

    self = self_alloc(self_map->data, self_map->size);
    if (!self)
      goto error;

    elf = elf_alloc(elf_map->data, elf_map->size, 0);
    if (!elf)
      goto error;

    new_self_data = (uint8_t*)malloc(self_map->size);
    if (!new_self_data)
      goto error;
    memset(new_self_data, 0, self_map->size);
    memcpy(new_self_data, self_map->data, self_map->size);

    new_self = self_alloc(new_self_data, self_map->size);
    if (!new_self)
      goto error;

    status = self_make_fake_signed(new_self, elf);
    if (!status) {
      warning("Unable to make fake signed elf.");
      goto error;
    }

    if (!write_to_file("eboot.fself", new_self_data, self_map->size, NULL, 0644))
      warning("Unable to write file.");

error:
    if (new_self)
      self_free(new_self);

    if (new_self_data)
      free(new_self_data);

    if (elf)
      elf_free(elf);

    if (self)
      self_free(self);

    if (elf_map)
      unmap_file(elf_map);

    if (self_map)
      unmap_file(self_map);

    return status;
  }
#endif

static enum cb_result pkg_pfs_unpack_pre_cb(void* arg, const char* path, enum pfs_entry_type type, int* needed) {
  const char* type_str;
  const char* tmp_path = path;
  const char* file_name = NULL;
  char** p;
  int match;

  UNUSED(arg);

  while (*tmp_path == '/')
    ++tmp_path;
  if (*tmp_path == '\0')
    tmp_path = path;

  if (type == PFS_ENTRY_FILE) {
    file_name = strrchr(tmp_path, '/');
    if (file_name)
      ++file_name;
    else
      file_name = tmp_path;
    if (file_name == tmp_path || *file_name == '\0')
      file_name = NULL;
  }

  if (s_file_paths) {
    p = NULL;
    match = 0;
    while ((p = (char**)utarray_next(s_file_paths, p))) {
      if (!*p)
        continue;
      if (wildcard_match(tmp_path, *p)) {
        match = 1;
        break;
      }
      if (file_name && wildcard_match(file_name, *p)) {
        match = 1;
        break;
      }
    }
  } else {
    match = 1;
  }

  if (match) {
    switch (type) {
      case PFS_ENTRY_FILE: type_str = "file"; break;
      case PFS_ENTRY_DIRECTORY: type_str = "directory"; break;
      default: type_str = "<unknown type>"; break;
    }

    info("Unpacking %s: %s", type_str, tmp_path);
  }

  if (needed)
    *needed = match;

  return CB_RESULT_CONTINUE;
}

static int tweak_pfs_options(struct pfs_options* opts, struct pkg* pkg) {
  int status = 0;

  assert(opts != NULL);

  if (s_no_signature_check > 0)
    opts->skip_signature_check = 1;
  if (s_no_icv_check > 0)
    opts->skip_block_hash_check = 1;

  if (pkg) {
    if (s_key_content_id)
      opts->content_id = pkg->hdr->content_id;
    if (s_key_content_id) {
      if (opts->keyset) {
        if (strcmp(opts->keyset->content_id, s_key_content_id) != 0)
          opts->keyset = keymgr_get_title_keyset(s_key_content_id);
      } else {
        opts->keyset = keymgr_get_title_keyset(s_key_content_id);
      }
    }
  } else {
#if defined(ENABLE_SD_KEYGEN)
    if (s_key_content_id && !opts->is_sd) {
#else
    if (s_key_content_id) {
#endif
      opts->keyset = keymgr_get_title_keyset(s_key_content_id);
    } else {
      opts->keyset = keymgr_alloc_title_keyset(KEYMGR_FAKE_CONTENT_ID, 0);
    }
  }

  if (opts->keyset) {
#if defined(ENABLE_SD_KEYGEN)
    if (s_passcode && !opts->is_sd) {
#else
    if (s_passcode) {
#endif
      memcpy(opts->keyset->passcode, s_passcode, sizeof(opts->keyset->passcode));
      opts->keyset->flags.has_passcode = 1;
    }
#if defined(ENABLE_SD_KEYGEN)
    if (s_sealed_key_file) {
      memset(opts->keyset->mkey, 0, sizeof(opts->keyset->mkey));
      if (!pfs_decrypt_sealed_key_from_file(s_sealed_key_file, opts->keyset->mkey))
        goto error;
      opts->keyset->flags.has_mkey = 1;
    }
#endif
    if (s_encdec_tweak_key) {
      memcpy(opts->keyset->enc_tweak_key, s_encdec_tweak_key, sizeof(opts->keyset->enc_tweak_key));
      opts->keyset->flags.has_enc_tweak_key = 1;
    }
    if (s_encdec_data_key) {
      memcpy(opts->keyset->enc_data_key, s_encdec_data_key, sizeof(opts->keyset->enc_data_key));
      opts->keyset->flags.has_enc_data_key = 1;
    }
    if (s_sign_key) {
      memcpy(opts->keyset->sig_hmac_key, s_sign_key, sizeof(opts->keyset->sig_hmac_key));
      opts->keyset->flags.has_sig_hmac_key = 1;
    }
    if (s_sc0_key) {
      memcpy(opts->keyset->sc0_key, s_sc0_key, sizeof(opts->keyset->sc0_key));
      opts->keyset->flags.has_sc0_key = 1;
    }
  }

  status = 1;

error:
  return status;
}

static int set_pkg_pfs_options_cb(void* arg, struct pkg* pkg, struct pfs_options* opts) {
  assert(pkg != NULL);
  assert(opts != NULL);

  UNUSED(arg);

  opts->disable_pkg_pfs_usage = (s_pfs != NULL);

  if (!s_gp4_file)
    opts->skip_keygen = s_no_unpack && s_unpack_sc_entries ? 1 : 0;

  if (s_cmd_info)
    opts->skip_keygen = 2;

  opts->dump_final_keys = s_dump_final_keys;
#if defined(ENABLE_SD_KEYGEN)
  opts->dump_sd_info = s_dump_sd_info;
#endif

  return tweak_pfs_options(opts, pkg);
}

static void cleanup_pfs(struct pfs_io_context* ctx) {
  assert(ctx != NULL);

  if (s_pfs) {
    pfs_free(s_pfs);
    s_pfs = NULL;
  }

  if (ctx->map)
    unmap_file(ctx->map);
}

static int setup_pfs(struct pfs_io_context* ctx, struct pfs_io_callbacks* io, const char* file_path, int inside_pkg) {
  struct pfs_options pfs_opts;

  assert(ctx != NULL);
  assert(io != NULL);
  assert(file_path != NULL);

  memset(ctx, 0, sizeof(*ctx));

  ctx->map = map_file(file_path);
  if (!ctx->map)
    goto error;

  ctx->offset = 0;

  memset(io, 0, sizeof(*io));
  {
    io->arg = ctx;
    io->get_size = &pfs_get_size_cb;
    io->get_outer_location = &pfs_get_outer_location_cb;
    io->get_offset_size = &pfs_get_offset_size_cb;
    io->seek = &pfs_seek_cb;
    io->read = &pfs_read_cb;
    io->write = &pfs_write_cb;
    io->can_seek = &pfs_can_seek_cb;
    io->can_read = &pfs_can_read_cb;
    io->can_write = &pfs_can_write_cb;
  }

  memset(&pfs_opts, 0, sizeof(pfs_opts));
  {
    pfs_opts.content_id = NULL;
    pfs_opts.finalized = 1;
    pfs_opts.playgo = 0;
    pfs_opts.case_sensitive = 0;
    pfs_opts.skip_signature_check = 1;
    pfs_opts.skip_block_hash_check = 0;
    pfs_opts.dump_final_keys = s_dump_final_keys;
#if defined(ENABLE_SD_KEYGEN)
    pfs_opts.dump_sd_info = s_dump_sd_info;
    pfs_opts.is_sd = !inside_pkg && s_sealed_key_file;
#else
    UNUSED(inside_pkg);
#endif
  }

  if (!tweak_pfs_options(&pfs_opts, NULL))
    goto error;

  s_pfs = pfs_alloc(io, &pfs_opts, 0);
  if (!s_pfs)
    goto error;

  return 1;

error:
  cleanup_pfs(ctx);

  return 0;
}

static int process_pfs(cmd_handler_t handler) {
  struct pfs_io_context ctx;
  struct pfs_io_callbacks io;
  int ret = 1;

  if (!setup_pfs(&ctx, &io, s_input_file_path, 0))
    goto error;

  if (handler)
    ret = (*handler)(&ctx.map->size);
  else
    ret = 1;

  cleanup_pfs(&ctx);

error:
  return ret;
}

static int pfs_info_handler(void* arg) {
  assert(s_pfs != NULL);

  UNUSED(arg);

  if (!pfs_info(s_pfs, 0, s_dump_sfo, s_backport, s_sdk_version))
    error("Unable to read info from PFS file: %s", s_input_file_path);

  return 0;
}

static int pfs_list_handler(void* arg) {
  assert(s_pfs != NULL);

  UNUSED(arg);

  if (!pfs_list_user_root_directory(s_pfs))
    error("Unable to list entries from PFS file: %s", s_input_file_path);

  return 0;
}

/* SELF/SPRX magic, for detecting encrypted executables in the unpacked tree. */
static const uint8_t s_self_magic[4] = { 0x4F, 0x15, 0x3D, 0x1D };
static const uint8_t s_elf_magic[4] = { 0x7F, 'E', 'L', 'F' };

struct unpack_postproc_ctx {
  int decrypt_elfs;
  int backport;
  int downgrade;
  int rewrap_fself;
  const char* sdk_version;
  uint32_t target_sdk;
  int decrypted;
  int backported;
  int downgraded;
  int rewrapped;
};

static int copy_file_bytes(const char* src, const char* dst) {
  FILE* in = fopen(src, "rb");
  FILE* out = NULL;
  uint8_t buf[65536];
  size_t n;
  int ok = 0;
  if (!in)
    return 0;
  out = fopen(dst, "wb");
  if (!out)
    goto done;
  while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
    if (fwrite(buf, 1, n, out) != n)
      goto done;
  }
  ok = ferror(in) ? 0 : 1;
done:
  if (out) fclose(out);
  fclose(in);
  return ok;
}

/* Decrypt a SELF file to plaintext ELF, replacing it in place (same path). */
static int decrypt_self_in_place(const char* path) {
  char tmp[PATH_MAX];
  snprintf(tmp, sizeof(tmp), "%s.__elf.tmp", path);
  if (!self_decrypt_file(path, tmp))
    return 0;
  remove(path);
  if (rename(tmp, path) != 0) {
    warning("Unable to replace '%s' with decrypted ELF.", path);
    remove(tmp);
    return 0;
  }
  return 1;
}

/* Extract the plaintext ELF from a fake-signed self, replacing it in place. */
static int unfself_in_place(const char* path) {
  char tmp[PATH_MAX];
  snprintf(tmp, sizeof(tmp), "%s.__elf.tmp", path);
  if (self_unfself_file(path, tmp) != 1) {
    remove(tmp);
    return 0;
  }
  remove(path);
  if (rename(tmp, path) != 0) {
    warning("Unable to replace '%s' with unfself'd ELF.", path);
    remove(tmp);
    return 0;
  }
  return 1;
}

/* Wrap a plaintext ELF back into a fake-signed self, replacing it in place. */
static int rewrap_fself_in_place(const char* path) {
  char tmp[PATH_MAX];
  snprintf(tmp, sizeof(tmp), "%s.__fself.tmp", path);
  if (self_make_fself_file(path, tmp, NULL) != 1) {
    remove(tmp);
    return 0;
  }
  remove(path);
  if (rename(tmp, path) != 0) {
    warning("Unable to replace '%s' with re-wrapped fake self.", path);
    remove(tmp);
    return 0;
  }
  return 1;
}

static enum cb_result unpack_postproc_cb(void* arg, const char* parent, const char* child, unsigned int mode) {
  struct unpack_postproc_ctx* ctx = (struct unpack_postproc_ctx*)arg;
  char path[PATH_MAX];

  if (!S_ISREG(mode))
    return CB_RESULT_CONTINUE;
  snprintf(path, sizeof(path), "%s/%s", parent, child);

  if (ctx->decrypt_elfs && file_has_magic(path, s_self_magic, sizeof(s_self_magic))) {
    info("Decrypting SELF: %s", child);
    if (decrypt_self_in_place(path)) {
      ctx->decrypted++;
    } else if (unfself_in_place(path)) {
      /* fake-signed self -> plaintext ELF extracted without decryption */
      info("Unfself'd fake-signed SELF: %s", child);
      ctx->decrypted++;
    }
  }

  /* Downgrade runs after decrypt so freshly-decrypted ELFs are covered too. */
  if (ctx->downgrade && file_has_magic(path, s_elf_magic, sizeof(s_elf_magic))) {
    int r = elf_downgrade_file(path, ctx->target_sdk);
    if (r == 1) {
      info("Downgraded ELF: %s", child);
      ctx->downgraded++;
    } else if (r < 0) {
      warning("Unable to downgrade '%s'.", child);
    }
  }

  /* Re-wrap plaintext ELFs (e.g. freshly decrypted + downgraded) back into a
     fake-signed self so a repacked PKG stays bootable. Runs last so it wraps
     the downgraded ELF. */
  if (ctx->rewrap_fself && file_has_magic(path, s_elf_magic, sizeof(s_elf_magic))) {
    if (rewrap_fself_in_place(path)) {
      info("Re-wrapped as fake-signed SELF: %s", child);
      ctx->rewrapped++;
    } else {
      warning("Unable to re-wrap '%s' as fake self.", child);
    }
  }

  if (ctx->backport && strcasecmp(child, "param.sfo") == 0) {
    struct sfo* sfo = sfo_alloc();
    if (sfo) {
      if (!sfo_load_from_file(sfo, path)) {
        warning("Unable to load '%s' for backporting.", path);
      } else {
        int rc = sfo_backport(sfo, ctx->sdk_version);
        if (rc == 0) {
          if (sfo_save_to_file(sfo, path)) {
            info("Backported SFO: %s", path);
            ctx->backported++;
          } else {
            warning("Unable to write backported '%s'.", path);
          }
        } else if (rc == 1) {
          info("SFO '%s' already at/below target SDK; left unchanged.", path);
        } else {
          warning("Unable to backport '%s' (error %d).", path, rc);
        }
      }
      sfo_free(sfo);
    }
  }
  return CB_RESULT_CONTINUE;
}

/* Post-unpack pass over the output tree: decrypt SELF/SPRX to ELF (--decrypt-elfs)
   and backport param.sfo (--backport). Runs on the whole unpacked directory. */
static void run_unpack_postproc(const char* dir) {
  struct unpack_postproc_ctx ctx;

  if (!s_decrypt_elfs && !s_backport && !s_downgrade && !s_rewrap_fself)
    return;

  memset(&ctx, 0, sizeof(ctx));
  ctx.decrypt_elfs = s_decrypt_elfs;
  ctx.backport = s_backport;
  ctx.downgrade = s_downgrade;
  ctx.rewrap_fself = s_rewrap_fself;
  ctx.sdk_version = s_sdk_version;
  ctx.target_sdk = s_sdk_version ? (uint32_t)strtoul(s_sdk_version, NULL, 16) : 0;

  list_directory_r(dir, &unpack_postproc_cb, &ctx);

  if (ctx.decrypted)
    info("Decrypted %d SELF/SPRX file(s) to plaintext ELF.", ctx.decrypted);
  if (ctx.downgraded)
    info("Downgraded %d ELF file(s).", ctx.downgraded);
  if (ctx.rewrapped)
    info("Re-wrapped %d ELF file(s) as fake-signed SELF.", ctx.rewrapped);
  if (ctx.backported)
    info("Backported %d param.sfo file(s).", ctx.backported);
}

static int pfs_unpack_handler(void* arg) {
  assert(s_pfs != NULL);

  UNUSED(arg);

  if (!s_no_unpack) {
    if (!pfs_unpack_all(s_pfs, s_output_directory, &pkg_pfs_unpack_pre_cb, NULL))
      error("Unable to unpack PFS file: %s", s_input_file_path);
  }

  /* DEBUG: dump internal inodes (blk_bitmap, ino_bitmap, block_addr_table, ...)
     decrypted, plus their physical block lists, to inspect the allocator format.
     Enable with env PFS_DUMP_INTERNAL. Remove after RE. */
  if (getenv("PFS_DUMP_INTERNAL")) {
    pfs_ino dump_inos[8];
    int n = 0, k;
    dump_inos[n++] = s_pfs->super_root_dir_ino;
    dump_inos[n++] = s_pfs->user_root_dir_ino;
    dump_inos[n++] = s_pfs->block_bitmap_ino;
    dump_inos[n++] = s_pfs->ino_bitmap_ino;
    dump_inos[n++] = s_pfs->block_addr_table_ino;
    fprintf(stderr, "[DUMP] super_root=%ju uroot=%ju blk_bitmap=%ju ino_bitmap=%ju bat=%ju\n",
      (uintmax_t)s_pfs->super_root_dir_ino, (uintmax_t)s_pfs->user_root_dir_ino,
      (uintmax_t)s_pfs->block_bitmap_ino, (uintmax_t)s_pfs->ino_bitmap_ino,
      (uintmax_t)s_pfs->block_addr_table_ino);
    fprintf(stderr, "[DUMP] nblock=%ju ndblock=%ju dinode_count=%ju dinode_block_count=%ju bbs=%zu\n",
      (uintmax_t)LE64(s_pfs->hdr.nblock), (uintmax_t)LE64(s_pfs->hdr.data_block_count),
      (uintmax_t)LE64(s_pfs->hdr.dinode_count), (uintmax_t)LE64(s_pfs->hdr.dinode_block_count),
      s_pfs->basic_block_size);
    for (k = 0; k < n; ++k) {
      struct pfs_file_context* f = pfs_get_file(s_pfs, dump_inos[k]);
      char path[PATH_MAX];
      FILE* fp;
      uint8_t* buf;
      uint64_t bi;
      if (!f) { fprintf(stderr, "[DUMP] ino %ju: get_file failed\n", (uintmax_t)dump_inos[k]); continue; }
      fprintf(stderr, "[DUMP] ino %ju: size=%ju blocks=%ju phys=[", (uintmax_t)dump_inos[k],
        (uintmax_t)f->file_size, (uintmax_t)(f->block_list ? f->block_list->count : 0));
      if (f->block_list) for (bi = 0; bi < f->block_list->count; ++bi)
        fprintf(stderr, "%ju ", (uintmax_t)f->block_list->blocks[bi]);
      fprintf(stderr, "]\n");
      buf = (uint8_t*)malloc(f->file_size ? (size_t)f->file_size : 1);
      if (buf && f->file_size && pfs_file_read(f, 0, buf, f->file_size)) {
        snprintf(path, sizeof(path), "%s/__ino%ju.bin", s_output_directory, (uintmax_t)dump_inos[k]);
        fp = fopen(path, "wb");
        if (fp) { fwrite(buf, 1, (size_t)f->file_size, fp); fclose(fp); }
      }
      free(buf);
      pfs_free_file(f);
    }
    /* Full inode -> physical block map, to correlate with BAT. */
    {
      uint64_t dc = LE64(s_pfs->hdr.dinode_count);
      uint64_t in;
      for (in = 0; in < dc && in < 64; ++in) {
        struct pfs_file_context* f = pfs_get_file(s_pfs, (pfs_ino)in);
        uint64_t bi;
        if (!f) continue;
        if (f->block_list && f->block_list->count) {
          fprintf(stderr, "[MAP] ino %ju type=%d size=%ju blocks=%ju phys=[", (uintmax_t)in,
            (int)f->type, (uintmax_t)f->file_size, (uintmax_t)f->block_list->count);
          for (bi = 0; bi < f->block_list->count; ++bi)
            fprintf(stderr, "%ju ", (uintmax_t)f->block_list->blocks[bi]);
          fprintf(stderr, "]\n");
        }
        pfs_free_file(f);
      }
    }
  }

  return 0;
}

#if defined(ENABLE_REPACK_SUPPORT)
  static int pfs_repack_dump_indirect_block_cb(void* arg, struct pfs* pfs, uint64_t block_no, uint64_t block_count, uint8_t* block_data) {
    struct pfs_repack_dump_indirect_block_cb_args* args = (struct pfs_repack_dump_indirect_block_cb_args*)arg;
    uint8_t* data;
    uint64_t data_size;
    int status = 0;

    assert(args != NULL);
    assert(args->map != NULL);
    assert(pfs != NULL);
    assert(block_data != NULL);

    data = args->map->data + pfs_block_no_to_offset(pfs, block_no);
    data_size = pfs_block_no_to_offset(pfs, block_count);

    memcpy(data, block_data, data_size);

    status = 1;

    return status;
  }

  static int pfs_repack_process_file(struct pfs* pfs, struct file_map* map, struct pfs_file_context* file, int as_is) {
    uint8_t* chunk;
    size_t chunk_size;
    uint64_t* blocks;
    uint8_t* data;
    uint64_t offset, size_left;
    uint64_t block_count;
    size_t block_size;
    size_t cur_size;
    uint64_t i; // FIXME: it was uint64_t
    int status = 0;

    assert(pfs != NULL);
    assert(file != NULL);

    if (file->dinode_block_no != 0) {
      data = map->data + pfs_block_no_to_offset(pfs, file->dinode_block_no) + file->dinode_offset;
      memcpy(data, &file->dinode, pfs->dinode_struct_size);
    }

    if (file->file_size > 0) {
      if (as_is) {
        assert(file->block_list != NULL);
        block_count = file->block_list->count;
        assert(block_count != 0);
        blocks = file->block_list->blocks;
        assert(blocks != NULL);

        block_size = pfs->basic_block_size;

        for (i = 0; i < block_count; ++i) {
        //for (i = block_count - 0; i >= 0; --i) {
          if (!pfs_read_blocks(pfs, blocks[i], file->tmp_block, 1))
            goto error;

#if 1 // FIXME
          data = map->data + pfs_block_no_to_offset(pfs, blocks[i]);
          memcpy(data, file->tmp_block, block_size);
#elif 0
          if (!pfs_write_blocks(pfs, blocks[i], file->tmp_block, 1))
            goto error;
#endif
        }
      } else {
        // TODO: need to rebuild blocks

        assert(file->block_list != NULL);
        block_count = file->block_list->count;
        assert(block_count != 0);
        blocks = file->block_list->blocks;
        assert(blocks != NULL);

        chunk = file->tmp_block;
        chunk_size = pfs->basic_block_size;

        data = map->data + pfs_block_no_to_offset(pfs, blocks[0]);

        for (i = 0; i < block_count; ++i) {
          printf("%ld ", blocks[i]);
        }
        printf("\n");

        memset(chunk, 0, chunk_size);

        offset = 0;
        size_left = file->file_size;
        while (size_left != 0) {
          cur_size = (size_left > chunk_size) ? chunk_size : (size_t)size_left;

          if (!pfs_file_read(file, offset, chunk, cur_size))
            goto error;

          memcpy(data, chunk, cur_size);

          data += cur_size;
          offset += cur_size;
          size_left -= cur_size;
        }
      }
    }

    status = 1;

error:
    return status;
  }

  static inline int pfs_repack_process_ino(struct pfs* pfs, struct file_map* map, pfs_ino ino, int as_is) {
    struct pfs_repack_dump_indirect_block_cb_args dump_args;
    struct pfs_file_context* file = NULL;
    int status = 0;

    assert(pfs != NULL);
    assert(map != NULL);

    memset(&dump_args, 0, sizeof(dump_args));

    dump_args.map = map;

    file = pfs_get_file_ex(pfs, ino, &pfs_repack_dump_indirect_block_cb, &dump_args);
    if (!file)
      goto error;

    status = pfs_repack_process_file(pfs, map, file, as_is);

error:
    if (file)
      pfs_free_file(file);

    return status;
  }

  static enum cb_result pfs_repack_process_dir_cb(void* arg, struct pfs* pfs, pfs_ino ino, enum pfs_entry_type type, const char* name) {
    struct pfs_repack_process_dir_cb_args* args = (struct pfs_repack_process_dir_cb_args*)arg;
    struct pfs_file_context* file = NULL;
    int as_is;
    uint8_t* data = NULL;

    assert(args != NULL);

    assert(pfs != NULL);

#    if defined(DECOMPRESS_INNER_PFS)
      as_is = strcmp(name, PKG_PFS_IMAGE_FILE_NAME) != 0;
#    else
      as_is = 1;
#    endif

    pfs_repack_process_ino(pfs, args->map, ino, as_is);

    file = pfs_get_file(pfs, ino);
    if (!file)
      goto error;

    if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
      if (type == PFS_ENTRY_DIRECTORY) {
        data = (uint8_t*)malloc(file->file_size);
        if (!data)
          goto error;
        memset(data, 0, file->file_size);

        if (!pfs_file_read(file, 0, data, file->file_size))
          goto error;

        pfs_parse_dir_entries(pfs, data, file->file_size, &pfs_repack_process_dir_cb, arg);
      }
    }

done:
    if (data)
      free(data);

    if (file)
      pfs_free_file(file);

    return CB_RESULT_CONTINUE;

error:
    warning("Unable to get file: %s", name);
    goto done;
  }

  static int pfs_repack_process_dir(struct pfs* pfs, struct file_map* map, pfs_ino dir_ino) {
    struct pfs_repack_process_dir_cb_args args;
    struct pfs_file_context* file = NULL;
    uint8_t* data = NULL;
    int status = 0;

    assert(pfs != NULL);
    assert(map != NULL);

    file = pfs_get_file(pfs, dir_ino);
    if (!file)
      goto error;

    status = pfs_repack_process_ino(pfs, map, dir_ino, 1);
    if (!status)
      goto error;

    data = (uint8_t*)malloc(file->file_size);
    if (!data)
      goto error;
    memset(data, 0, file->file_size);

    if (!pfs_file_read(file, 0, data, file->file_size))
      goto error;

    memset(&args, 0, sizeof(args));
    {
      args.map = map;
    }

    pfs_parse_dir_entries(pfs, data, file->file_size, &pfs_repack_process_dir_cb, &args);

    status = 1;

error:
    if (data)
      free(data);

    if (file)
      pfs_free_file(file);

    return status;
  }

  static int pfs_repack_internal(struct pfs* pfs, struct file_map* map) {
    struct pfs_header hdr;
    uint8_t* header_data = NULL;
    int status = 0;

    assert(pfs != NULL);
    assert(map != NULL);

    memcpy(&hdr, &pfs->hdr, sizeof(pfs->hdr));

    //hdr.mode &= ~LE16(PFS_MODE_SIGNED_FLAG);
    //hdr.mode &= ~LE16(PFS_MODE_ENCRYPTED_FLAG); // FIXME: uncomment

    header_data = (uint8_t*)malloc(PFS_HEADER_SIZE);
    if (!header_data)
      goto error;
    memset(header_data, 0, PFS_HEADER_SIZE);
    memcpy(header_data, &hdr, PFS_HEADER_COVER_SIZE_FOR_ICV);
    pfs_sign_buffer(pfs, header_data, PFS_HEADER_SIZE, hdr.header_hash);

    memcpy(map->data, &hdr, sizeof(hdr));

    //pfs_repack_process_ino(s_pfs, map, s_pfs->super_root_dir_ino);
    /*if (s_pfs->block_bitmap_ino > 0)
      pfs_repack_process_ino(s_pfs, map, s_pfs->block_bitmap_ino);
    if (s_pfs->ino_bitmap_ino > 0)
      pfs_repack_process_ino(s_pfs, map, s_pfs->ino_bitmap_ino);
    if (s_pfs->user_root_dir_ino > 0)
      pfs_repack_process_ino(s_pfs, map, s_pfs->user_root_dir_ino);
    if (s_pfs->block_addr_table_ino > 0)
      pfs_repack_process_ino(s_pfs, map, s_pfs->block_addr_table_ino);
    if (s_pfs->flat_path_table_ino > 0)
      pfs_repack_process_ino(s_pfs, map, s_pfs->flat_path_table_ino);
    if (s_pfs->collision_resolver_ino > 0)
      pfs_repack_process_ino(s_pfs, map, s_pfs->collision_resolver_ino);*/

    /*
    super_root_dir_ino = 0
    block_bitmap_ino = 2
    ino_bitmap_ino = 4
    user_root_dir_ino = 1
    block_addr_table_ino = 5
    flat_path_table_ino = 0
    collision_resolver_ino = 0
    */

    pfs_repack_process_dir(pfs, map, pfs->super_root_dir_ino);
    //pfs_repack_process_dir(pfs, map, pfs->user_root_dir_ino);

    status = 1;

error:
    if (header_data)
      free(header_data);

    return status;
  }

  /* Implemented after Stage 1 verification; see definition below. */
  static int pfs_repack_apply_mods(struct pfs* pfs, struct file_map* map, const char* mod_dir);

  static int pfs_repack_handler(void* arg) {
    uint64_t file_size;
    struct file_map* src_map = NULL;
    struct file_map* map = NULL;
    int status = 1; /* main() treats non-zero as failure (uses `!= 0`) */

    assert(s_pfs != NULL);
    assert(arg != NULL);

    file_size = *(uint64_t*)arg;

    /*
     * Repack baseline = verbatim copy of the source image.
     *
     * A raw SD/savedata PFS is a fixed-size, signed + encrypted image: every
     * data block carries an HMAC digest inside its (signed) inode, the header
     * is HMAC-signed and there is an SD auth code. flatz's original block-by-
     * block re-serializer wrote *decrypted* blocks back as plaintext and never
     * rebuilt those digests, producing a corrupt image. Copying the original
     * bytes preserves all encryption, digests and signatures, so an unmodified
     * repack round-trips identically and stays console-valid. Modifications are
     * then applied as surgical, same-size patches (see pfs_repack_apply_mods).
     */
    src_map = map_file(s_input_file_path);
    if (!src_map) {
      warning("Unable to open input image for repack: %s", s_input_file_path);
      goto error;
    }
    if (src_map->size != file_size) {
      warning("Unexpected input image size (expected 0x%" PRIX64 ", got 0x%" PRIX64 ").", file_size, (uint64_t)src_map->size);
      goto error;
    }

    map = map_file_for_write(s_output_file_path, file_size, 0644);
    if (!map)
      goto error;

    memcpy(map->data, src_map->data, (size_t)file_size);

#if defined(ENABLE_REPACK_SUPPORT)
    if (s_plaintext_elf_directory) {
      /* s_plaintext_elf_directory doubles as the modified-files directory for raw PFS repack. */
      if (!pfs_repack_apply_mods(s_pfs, map, s_plaintext_elf_directory))
        goto error;
    }
#endif

    status = 0; /* success */

error:
    if (map)
      unmap_file(map);
    if (src_map)
      unmap_file(src_map);

    return status;
  }

  /*
   * Write one basic block of plaintext into the output image at physical block
   * `phys`: XTS-encrypt it (whole-image encryption, matching pfs_read_blocks),
   * store it, and return the block's signed digest = HMAC(sig_hmac_key, ciphertext).
   */
  static int pfs_repack_write_block(struct pfs* pfs, struct file_map* map, uint64_t phys, const uint8_t* plain, uint8_t digest[PFS_HASH_SIZE]) {
    size_t bbs = pfs->basic_block_size;
    uint64_t off = pfs_block_no_to_offset(pfs, phys);
    uint8_t* cipher = (uint8_t*)malloc(bbs);
    if (!cipher)
      return 0;
    if (pfs->is_encrypted)
      pfs_encrypt(pfs, plain, cipher, off, bbs);
    else
      memcpy(cipher, plain, bbs);
    memcpy(map->data + off, cipher, bbs);
    pfs_sign_buffer(pfs, cipher, bbs, digest);
    free(cipher);
    return 1;
  }

  /* Read a basic block back from the (progressively updated) output image, decrypted. */
  static void pfs_repack_read_out_block(struct pfs* pfs, struct file_map* map, uint64_t phys, uint8_t* plain) {
    size_t bbs = pfs->basic_block_size;
    uint64_t off = pfs_block_no_to_offset(pfs, phys);
    if (pfs->is_encrypted)
      pfs_decrypt(pfs, map->data + off, plain, off, bbs);
    else
      memcpy(plain, map->data + off, bbs);
  }

  /*
   * Replace the contents of one regular file (same size) in the output image and
   * fix up every digest on the path from its data blocks to the super root:
   *   data block -> file sdinode direct/indirect digest
   *   (single-level) indirect block -> file sdinode indirect digest
   *   file's dinode block -> super_root_dinode digest (kept in pfs->hdr in memory)
   * The header itself is re-signed once, after all files, by the caller.
   */
  static int pfs_repack_patch_file(struct pfs* pfs, struct file_map* map, pfs_ino ino, const uint8_t* new_data, uint64_t new_size) {
    struct pfs_file_context* file = NULL;
    uint8_t* plain = NULL;
    uint8_t* indbuf = NULL;
    uint8_t* dblock = NULL;
    size_t bbs = pfs->basic_block_size;
    uint64_t block_count, i, ind_block_no = 0;
    size_t idx1;
    uint8_t digest[PFS_HASH_SIZE];
    int status = 0;

    if (pfs->format != PFS_FORMAT_32_SIGNED) {
      warning("Modification only supported for 32-bit signed PFS.");
      goto error;
    }

    file = pfs_get_file(pfs, ino);
    if (!file) {
      warning("Unable to load file (ino %" PRIuMAX ") for modification.", (uintmax_t)ino);
      goto error;
    }

    if (file->flags & PFS_FILE_COMPRESSED) {
      warning("Skipping compressed file (ino %" PRIuMAX "): recompression not supported.", (uintmax_t)ino);
      status = 1; /* non-fatal: leave original content */
      goto error;
    }
    if (new_size != file->file_size) {
      warning("Skipping ino %" PRIuMAX ": size differs.", (uintmax_t)ino);
      status = 1;
      goto error;
    }

    block_count = file->block_list->count;
    if (block_count > (uint64_t)PFS_DIRECT_BLOCK_MAX_COUNT + pfs->indirect_ptrs_per_block) {
      warning("Skipping ino %" PRIuMAX ": file too large (multi-level indirect not supported).", (uintmax_t)ino);
      status = 1;
      goto error;
    }

    plain = (uint8_t*)malloc(bbs);
    if (!plain)
      goto error;

    if (block_count > (uint64_t)PFS_DIRECT_BLOCK_MAX_COUNT) {
      ind_block_no = LE32(file->dinode.sdi32.indirect_blocks[0].block_no);
      indbuf = (uint8_t*)malloc(bbs);
      if (!indbuf)
        goto error;
      pfs_repack_read_out_block(pfs, map, ind_block_no, indbuf);
    }

    for (i = 0; i < block_count; ++i) {
      uint64_t phys = file->block_list->blocks[i];
      uint64_t off = i * bbs;
      uint64_t csz = (new_size - off > bbs) ? bbs : (new_size - off);

      memset(plain, 0, bbs);
      memcpy(plain, new_data + off, (size_t)csz);

      if (!pfs_repack_write_block(pfs, map, phys, plain, digest))
        goto error;

      if (i < (uint64_t)PFS_DIRECT_BLOCK_MAX_COUNT) {
        memcpy(file->dinode.sdi32.direct_blocks[i].digest, digest, PFS_HASH_SIZE);
      } else {
        struct pfs_sblock32* ent = (struct pfs_sblock32*)(indbuf + (size_t)(i - PFS_DIRECT_BLOCK_MAX_COUNT) * pfs->block_info_struct_size);
        memcpy(ent->digest, digest, PFS_HASH_SIZE);
      }
    }

    if (block_count > (uint64_t)PFS_DIRECT_BLOCK_MAX_COUNT) {
      if (!pfs_repack_write_block(pfs, map, ind_block_no, indbuf, digest))
        goto error;
      memcpy(file->dinode.sdi32.indirect_blocks[0].digest, digest, PFS_HASH_SIZE);
    }

    /* Write the (patched) dinode block, reading the current output so multiple
       inodes sharing a dinode block accumulate correctly. */
    dblock = (uint8_t*)malloc(bbs);
    if (!dblock)
      goto error;
    pfs_repack_read_out_block(pfs, map, file->dinode_block_no, dblock);
    memcpy(dblock + file->dinode_offset, &file->dinode, pfs->dinode_struct_size);
    if (!pfs_repack_write_block(pfs, map, file->dinode_block_no, dblock, digest))
      goto error;

    idx1 = (size_t)(ino / pfs->inodes_per_block);
    if (idx1 >= (size_t)PFS_DIRECT_BLOCK_MAX_COUNT) {
      warning("Super root indirect dinode blocks not supported (ino %" PRIuMAX ").", (uintmax_t)ino);
      goto error;
    }
    memcpy(pfs->hdr.super_root_dinode.sdi64.direct_blocks[idx1].digest, digest, PFS_HASH_SIZE);

    status = 1;

error:
    if (plain)
      free(plain);
    if (indbuf)
      free(indbuf);
    if (dblock)
      free(dblock);
    if (file)
      pfs_free_file(file);

    return status;
  }

  struct pfs_repack_mod_ctx {
    struct pfs* pfs;
    struct file_map* map;
    const char* mod_dir;
    int error;
    int changed;

    /* Allocator state for resize (shrink/grow). Decrypted copies of the
       blk_bitmap and block_addr_table (BAT) files; edited in memory as blocks
       are freed/allocated, then flushed + re-signed once at the end. */
    uint8_t* bitmap;      uint64_t bitmap_size;
    uint8_t* bat;         uint64_t bat_size;
    uint8_t* ino_bitmap;  uint64_t ino_bitmap_size; /* for add/remove (inode alloc) */
    int meta_loaded;      /* bitmap+bat successfully read */
    int meta_dirty;       /* needs flush/re-sign */
  };

  /* Free a physical block in the allocator metadata: clear its blk_bitmap bit
     (1=used, LSB-first) and its BAT owner entry. */
  static void pfs_repack_meta_free_block(struct pfs_repack_mod_ctx* ctx, uint64_t phys) {
    if (!ctx->meta_loaded)
      return;
    if (ctx->bitmap && (phys / 8) < ctx->bitmap_size)
      ctx->bitmap[phys / 8] &= (uint8_t)~(1u << (phys % 8));
    if (ctx->bat && (phys * 4 + 4) <= ctx->bat_size)
      *(uint32_t*)(ctx->bat + phys * 4) = 0;
    ctx->meta_dirty = 1;
  }

  /* Allocate one physical block from the SAFE free pool: bitmap bit == 0 AND
     BAT == 0 (both agree free). The nbackup=1 backup generation makes the
     bitmap alone unreliable, so the intersection is the only safe pool (see
     ps4-savedata-pfs-allocator-format). Marks it used (bitmap=1, BAT=bat_value)
     and returns the physical block number, or 0 if the pool is exhausted
     (block 0 is the header, never a valid data block, so it doubles as the
     failure sentinel). */
  static uint64_t pfs_repack_meta_alloc_block(struct pfs_repack_mod_ctx* ctx, uint32_t bat_value) {
    uint64_t total, phys;
    if (!ctx->meta_loaded || !ctx->bitmap || !ctx->bat)
      return 0;
    total = ctx->bitmap_size * 8;
    if (ctx->bat_size / 4 < total)
      total = ctx->bat_size / 4;
    for (phys = 1; phys < total; ++phys) {
      if (ctx->bitmap[phys / 8] & (uint8_t)(1u << (phys % 8)))
        continue;                                      /* bitmap: used */
      if (*(uint32_t*)(ctx->bat + phys * 4) != 0)
        continue;                                      /* BAT: owned (backup-gen) */
      ctx->bitmap[phys / 8] |= (uint8_t)(1u << (phys % 8));
      *(uint32_t*)(ctx->bat + phys * 4) = LE32(bat_value);
      ctx->meta_dirty = 1;
      return phys;
    }
    return 0;
  }

  /*
   * Shrink one regular file to new_size (< current size): rewrite the kept
   * blocks, free the tail data (and indirect) blocks in blk_bitmap+BAT, truncate
   * the inode, and re-sign the Merkle path up to the super root. The edited
   * blk_bitmap/BAT are flushed + re-signed once by the caller (apply_mods).
   */
  static int pfs_repack_shrink_file(struct pfs* pfs, struct pfs_repack_mod_ctx* ctx, pfs_ino ino, const uint8_t* new_data, uint64_t new_size) {
    struct file_map* map = ctx->map;
    struct pfs_file_context* file = NULL;
    uint8_t* plain = NULL;
    uint8_t* indbuf = NULL;
    uint8_t* dblock = NULL;
    size_t bbs = pfs->basic_block_size;
    uint64_t old_count, new_count, i, ind_block_no = 0;
    size_t idx1;
    uint8_t digest[PFS_HASH_SIZE];
    int old_ind, new_ind;
    int status = 0;

    if (pfs->format != PFS_FORMAT_32_SIGNED) {
      warning("Resize only supported for 32-bit signed PFS.");
      goto error;
    }
    if (!ctx->meta_loaded) {
      warning("Allocator metadata (blk_bitmap/BAT) unavailable; cannot resize.");
      goto error;
    }

    file = pfs_get_file(pfs, ino);
    if (!file) {
      warning("Unable to load file (ino %" PRIuMAX ") for shrink.", (uintmax_t)ino);
      goto error;
    }
    if (file->flags & PFS_FILE_COMPRESSED) {
      warning("Skipping compressed file (ino %" PRIuMAX "): resize not supported.", (uintmax_t)ino);
      status = 1;
      goto error;
    }
    if (new_size == 0 || new_size >= file->file_size) {
      warning("Skipping ino %" PRIuMAX ": shrink target invalid (0 or not smaller).", (uintmax_t)ino);
      status = 1;
      goto error;
    }

    old_count = file->block_list->count;
    new_count = (new_size + bbs - 1) / bbs;
    old_ind = old_count > (uint64_t)PFS_DIRECT_BLOCK_MAX_COUNT;
    new_ind = new_count > (uint64_t)PFS_DIRECT_BLOCK_MAX_COUNT;

    if (old_count > (uint64_t)PFS_DIRECT_BLOCK_MAX_COUNT + pfs->indirect_ptrs_per_block) {
      warning("Skipping ino %" PRIuMAX ": multi-level indirect not supported.", (uintmax_t)ino);
      status = 1;
      goto error;
    }

    plain = (uint8_t*)malloc(bbs);
    if (!plain)
      goto error;
    if (old_ind)
      ind_block_no = LE32(file->dinode.sdi32.indirect_blocks[0].block_no);
    if (new_ind) {
      indbuf = (uint8_t*)malloc(bbs);
      if (!indbuf)
        goto error;
      memset(indbuf, 0, bbs);
    }

    /* Rewrite kept blocks (last one zero-padded) and record their digests. */
    for (i = 0; i < new_count; ++i) {
      uint64_t phys = file->block_list->blocks[i];
      uint64_t off = i * bbs;
      uint64_t csz = (new_size - off > bbs) ? bbs : (new_size - off);

      memset(plain, 0, bbs);
      memcpy(plain, new_data + off, (size_t)csz);

      if (!pfs_repack_write_block(pfs, map, phys, plain, digest))
        goto error;

      if (i < (uint64_t)PFS_DIRECT_BLOCK_MAX_COUNT) {
        memcpy(file->dinode.sdi32.direct_blocks[i].digest, digest, PFS_HASH_SIZE);
      } else {
        struct pfs_sblock32* ent = (struct pfs_sblock32*)(indbuf + (size_t)(i - PFS_DIRECT_BLOCK_MAX_COUNT) * pfs->block_info_struct_size);
        memcpy(ent->digest, digest, PFS_HASH_SIZE);
        ent->block_no = LE32((uint32_t)phys);
      }
    }

    /* Free the tail data blocks no longer referenced. */
    for (i = new_count; i < old_count; ++i)
      pfs_repack_meta_free_block(ctx, file->block_list->blocks[i]);

    /* Indirect block: re-sign if still used, else free it. */
    if (new_ind) {
      if (!pfs_repack_write_block(pfs, map, ind_block_no, indbuf, digest))
        goto error;
      memcpy(file->dinode.sdi32.indirect_blocks[0].digest, digest, PFS_HASH_SIZE);
    } else if (old_ind) {
      pfs_repack_meta_free_block(ctx, ind_block_no);
      memset(&file->dinode.sdi32.indirect_blocks[0], 0, sizeof(file->dinode.sdi32.indirect_blocks[0]));
    }

    /* Zero freed direct-block inode slots. */
    for (i = new_count; i < (uint64_t)PFS_DIRECT_BLOCK_MAX_COUNT; ++i)
      memset(&file->dinode.sdi32.direct_blocks[i], 0, sizeof(file->dinode.sdi32.direct_blocks[i]));

    file->dinode.size = LE64(new_size);
    file->dinode.size_uncompressed = LE64(new_size);
    file->dinode.sdi32.block_count = LE32((uint32_t)new_count);

    /* Write the truncated dinode block and re-sign up to the super root. */
    dblock = (uint8_t*)malloc(bbs);
    if (!dblock)
      goto error;
    pfs_repack_read_out_block(pfs, map, file->dinode_block_no, dblock);
    memcpy(dblock + file->dinode_offset, &file->dinode, pfs->dinode_struct_size);
    if (!pfs_repack_write_block(pfs, map, file->dinode_block_no, dblock, digest))
      goto error;

    idx1 = (size_t)(ino / pfs->inodes_per_block);
    if (idx1 >= (size_t)PFS_DIRECT_BLOCK_MAX_COUNT) {
      warning("Super root indirect dinode blocks not supported (ino %" PRIuMAX ").", (uintmax_t)ino);
      goto error;
    }
    memcpy(pfs->hdr.super_root_dinode.sdi64.direct_blocks[idx1].digest, digest, PFS_HASH_SIZE);

    status = 1;

error:
    if (plain)
      free(plain);
    if (indbuf)
      free(indbuf);
    if (dblock)
      free(dblock);
    if (file)
      pfs_free_file(file);

    return status;
  }

  /*
   * Grow one regular file to new_size (> current size): allocate the extra data
   * blocks from the safe free pool, (re)write every block from new_data, extend
   * the inode (allocating an indirect block when crossing 12 direct blocks), and
   * re-sign the Merkle path up to the super root. Container size stays fixed —
   * only existing free blocks are reused. The edited blk_bitmap/BAT are flushed
   * + re-signed once by the caller (apply_mods). Mirror of pfs_repack_shrink_file.
   */
  static int pfs_repack_grow_file(struct pfs* pfs, struct pfs_repack_mod_ctx* ctx, pfs_ino ino, const uint8_t* new_data, uint64_t new_size) {
    struct file_map* map = ctx->map;
    struct pfs_file_context* file = NULL;
    uint8_t* plain = NULL;
    uint8_t* indbuf = NULL;
    uint8_t* dblock = NULL;
    uint64_t* newphys = NULL;   /* physical block for each logical index 0..new_count-1 */
    size_t bbs = pfs->basic_block_size;
    uint64_t old_count, new_count, i, ind_block_no = 0;
    size_t idx1;
    uint8_t digest[PFS_HASH_SIZE];
    int old_ind, new_ind;
    int status = 0;

    if (pfs->format != PFS_FORMAT_32_SIGNED) {
      warning("Resize only supported for 32-bit signed PFS.");
      goto error;
    }
    if (!ctx->meta_loaded) {
      warning("Allocator metadata (blk_bitmap/BAT) unavailable; cannot resize.");
      goto error;
    }

    file = pfs_get_file(pfs, ino);
    if (!file) {
      warning("Unable to load file (ino %" PRIuMAX ") for grow.", (uintmax_t)ino);
      goto error;
    }
    if (file->flags & PFS_FILE_COMPRESSED) {
      warning("Skipping compressed file (ino %" PRIuMAX "): resize not supported.", (uintmax_t)ino);
      status = 1;
      goto error;
    }
    if (new_size <= file->file_size) {
      warning("Skipping ino %" PRIuMAX ": grow target invalid (not larger).", (uintmax_t)ino);
      status = 1;
      goto error;
    }

    old_count = file->block_list->count;
    new_count = (new_size + bbs - 1) / bbs;
    old_ind = old_count > (uint64_t)PFS_DIRECT_BLOCK_MAX_COUNT;
    new_ind = new_count > (uint64_t)PFS_DIRECT_BLOCK_MAX_COUNT;

    if (new_count > (uint64_t)PFS_DIRECT_BLOCK_MAX_COUNT + pfs->indirect_ptrs_per_block) {
      warning("Skipping ino %" PRIuMAX ": file too large (multi-level indirect not supported).", (uintmax_t)ino);
      status = 1;
      goto error;
    }

    plain = (uint8_t*)malloc(bbs);
    newphys = (uint64_t*)malloc((size_t)new_count * sizeof(uint64_t));
    if (!plain || !newphys)
      goto error;

    /* Keep the existing blocks (same phys); the new ones are allocated below. */
    for (i = 0; i < old_count; ++i)
      newphys[i] = file->block_list->blocks[i];

    /*
     * Reserve all new physical blocks up front so a short free pool fails before
     * any block is written. Indirect block first (owned by the inode: BAT=ino),
     * then data blocks (direct -> BAT=ino; indirect-referenced -> BAT=0x80000000|ib).
     */
    if (new_ind && !old_ind) {
      ind_block_no = pfs_repack_meta_alloc_block(ctx, (uint32_t)ino);
      if (!ind_block_no) {
        warning("No free block for indirect block (ino %" PRIuMAX "); free pool exhausted.", (uintmax_t)ino);
        goto error;
      }
    } else if (old_ind) {
      ind_block_no = LE32(file->dinode.sdi32.indirect_blocks[0].block_no);
    }

    for (i = old_count; i < new_count; ++i) {
      uint32_t bat_val = (i < (uint64_t)PFS_DIRECT_BLOCK_MAX_COUNT)
                           ? (uint32_t)ino
                           : (0x80000000u | (uint32_t)ind_block_no);
      uint64_t phys = pfs_repack_meta_alloc_block(ctx, bat_val);
      if (!phys) {
        warning("No free blocks to grow ino %" PRIuMAX " (need %" PRIuMAX " more); free pool exhausted.",
                (uintmax_t)ino, (uintmax_t)(new_count - i));
        goto error;
      }
      newphys[i] = phys;
    }

    if (new_ind) {
      indbuf = (uint8_t*)malloc(bbs);
      if (!indbuf)
        goto error;
      memset(indbuf, 0, bbs);
    }

    /* (Re)write every block from new_data (last one zero-padded) and record its
       digest + block_no; kept blocks are rewritten too so a previously partial
       last block picks up the new tail bytes. */
    for (i = 0; i < new_count; ++i) {
      uint64_t phys = newphys[i];
      uint64_t off = i * bbs;
      uint64_t csz = (new_size - off > bbs) ? bbs : (new_size - off);

      memset(plain, 0, bbs);
      memcpy(plain, new_data + off, (size_t)csz);

      if (!pfs_repack_write_block(pfs, map, phys, plain, digest))
        goto error;

      if (i < (uint64_t)PFS_DIRECT_BLOCK_MAX_COUNT) {
        memcpy(file->dinode.sdi32.direct_blocks[i].digest, digest, PFS_HASH_SIZE);
        file->dinode.sdi32.direct_blocks[i].block_no = LE32((uint32_t)phys);
      } else {
        struct pfs_sblock32* ent = (struct pfs_sblock32*)(indbuf + (size_t)(i - PFS_DIRECT_BLOCK_MAX_COUNT) * pfs->block_info_struct_size);
        memcpy(ent->digest, digest, PFS_HASH_SIZE);
        ent->block_no = LE32((uint32_t)phys);
      }
    }

    if (new_ind) {
      if (!pfs_repack_write_block(pfs, map, ind_block_no, indbuf, digest))
        goto error;
      memcpy(file->dinode.sdi32.indirect_blocks[0].digest, digest, PFS_HASH_SIZE);
      file->dinode.sdi32.indirect_blocks[0].block_no = LE32((uint32_t)ind_block_no);
    }

    file->dinode.size = LE64(new_size);
    file->dinode.size_uncompressed = LE64(new_size);
    file->dinode.sdi32.block_count = LE32((uint32_t)new_count);

    /* Write the extended dinode block and re-sign up to the super root. */
    dblock = (uint8_t*)malloc(bbs);
    if (!dblock)
      goto error;
    pfs_repack_read_out_block(pfs, map, file->dinode_block_no, dblock);
    memcpy(dblock + file->dinode_offset, &file->dinode, pfs->dinode_struct_size);
    if (!pfs_repack_write_block(pfs, map, file->dinode_block_no, dblock, digest))
      goto error;

    idx1 = (size_t)(ino / pfs->inodes_per_block);
    if (idx1 >= (size_t)PFS_DIRECT_BLOCK_MAX_COUNT) {
      warning("Super root indirect dinode blocks not supported (ino %" PRIuMAX ").", (uintmax_t)ino);
      goto error;
    }
    memcpy(pfs->hdr.super_root_dinode.sdi64.direct_blocks[idx1].digest, digest, PFS_HASH_SIZE);

    status = 1;

error:
    if (plain)
      free(plain);
    if (indbuf)
      free(indbuf);
    if (dblock)
      free(dblock);
    if (newphys)
      free(newphys);
    if (file)
      pfs_free_file(file);

    return status;
  }

  /* =====================================================================
   * Add / remove files and directories (in-place, container size fixed).
   *
   * All inode/dirent resolution reads through the output `map` (not the
   * source image) so freshly added inodes/dirents are visible immediately.
   * A dinode's physical block never moves, so its location comes straight
   * from the in-memory super root (pfs_repack_dinode_loc) and the block is
   * read/written in `map`. Blocks come from the SAFE pool (bitmap==0 AND
   * BAT==0); inodes from the SAFE pool (ino_bitmap==0 AND dinode empty).
   * ===================================================================== */

  /* Physical dinode block + offset for an inode, from the in-memory super root.
     Fails if the inode falls in an indirect super-root dinode block (idx>=12). */
  static int pfs_repack_dinode_loc(struct pfs* pfs, pfs_ino ino, uint64_t* blkno, size_t* off) {
    size_t idx1 = (size_t)(ino / pfs->inodes_per_block);
    size_t idx2 = (size_t)(ino % pfs->inodes_per_block);
    if (idx1 >= (size_t)PFS_DIRECT_BLOCK_MAX_COUNT)
      return 0;
    *blkno = LE64(pfs->hdr.super_root_dinode.sdi64.direct_blocks[idx1].block_no);
    *off = idx2 * pfs->dinode_struct_size;
    return 1;
  }

  static int pfs_repack_read_dinode(struct pfs* pfs, struct file_map* map, pfs_ino ino, struct pfs_dinode* dinode) {
    uint64_t blkno; size_t off;
    uint8_t* blk;
    if (!pfs_repack_dinode_loc(pfs, ino, &blkno, &off))
      return 0;
    blk = (uint8_t*)malloc(pfs->basic_block_size);
    if (!blk)
      return 0;
    pfs_repack_read_out_block(pfs, map, blkno, blk);
    memcpy(dinode, blk + off, pfs->dinode_struct_size);
    free(blk);
    return 1;
  }

  /* Collect a file/dir's physical data-block numbers from its dinode (via map).
     Single-level indirect only; *ind_block set to the indirect block (0 if none).
     Returns malloc'd array (caller frees) or NULL on error; *count set. */
  static uint64_t* pfs_repack_collect_blocks(struct pfs* pfs, struct file_map* map, const struct pfs_dinode* dinode, uint64_t* count, uint64_t* ind_block) {
    uint64_t bc = LE32(dinode->sdi32.block_count);
    uint64_t* blocks; uint8_t* indbuf; uint64_t i;
    *ind_block = 0; *count = 0;
    if (bc > (uint64_t)PFS_DIRECT_BLOCK_MAX_COUNT + pfs->indirect_ptrs_per_block)
      return NULL;
    blocks = (uint64_t*)malloc((size_t)(bc ? bc : 1) * sizeof(uint64_t));
    if (!blocks)
      return NULL;
    for (i = 0; i < bc && i < (uint64_t)PFS_DIRECT_BLOCK_MAX_COUNT; ++i)
      blocks[i] = LE32(dinode->sdi32.direct_blocks[i].block_no);
    if (bc > (uint64_t)PFS_DIRECT_BLOCK_MAX_COUNT) {
      *ind_block = LE32(dinode->sdi32.indirect_blocks[0].block_no);
      indbuf = (uint8_t*)malloc(pfs->basic_block_size);
      if (!indbuf) { free(blocks); return NULL; }
      pfs_repack_read_out_block(pfs, map, *ind_block, indbuf);
      for (i = (uint64_t)PFS_DIRECT_BLOCK_MAX_COUNT; i < bc; ++i) {
        struct pfs_sblock32* ent = (struct pfs_sblock32*)(indbuf + (size_t)(i - PFS_DIRECT_BLOCK_MAX_COUNT) * pfs->block_info_struct_size);
        blocks[i] = LE32(ent->block_no);
      }
      free(indbuf);
    }
    *count = bc;
    return blocks;
  }

  /* Read `out_size` bytes of an inode's content from map given its dinode. */
  static int pfs_repack_read_content(struct pfs* pfs, struct file_map* map, const struct pfs_dinode* dinode, uint8_t* out, uint64_t out_size) {
    uint64_t count, ind, i;
    size_t bbs = pfs->basic_block_size;
    uint64_t* blocks = pfs_repack_collect_blocks(pfs, map, dinode, &count, &ind);
    uint8_t* blk;
    if (!blocks)
      return 0;
    blk = (uint8_t*)malloc(bbs);
    if (!blk) { free(blocks); return 0; }
    for (i = 0; i < count; ++i) {
      uint64_t off = i * bbs;
      uint64_t csz;
      if (out_size <= off) break;
      csz = (out_size - off > bbs) ? bbs : (out_size - off);
      pfs_repack_read_out_block(pfs, map, blocks[i], blk);
      memcpy(out + off, blk, (size_t)csz);
    }
    free(blk); free(blocks);
    return 1;
  }

  /* Find dirent `name` in a directory content buffer. */
  static int pfs_repack_dir_find(const uint8_t* buf, uint64_t size, const char* name, uint32_t* out_ino, uint32_t* out_type, uint64_t* out_off, uint32_t* out_entsize) {
    uint64_t p = 0;
    size_t nlen = strlen(name);
    while (p + PFS_MIN_DIR_ENTRY_SIZE <= size) {
      const struct pfs_dir_entry* e = (const struct pfs_dir_entry*)(buf + p);
      uint32_t eino = LE32(e->ino), es = LE32(e->entry_size), ns = LE32(e->name_size);
      if (eino == 0 || es == 0) break;
      if (ns == nlen && memcmp(e->name, name, nlen) == 0) {
        if (out_ino) *out_ino = eino;
        if (out_type) *out_type = LE32(e->type);
        if (out_off) *out_off = p;
        if (out_entsize) *out_entsize = es;
        return 1;
      }
      p += es;
    }
    return 0;
  }

  static int pfs_repack_lookup_child(struct pfs* pfs, struct file_map* map, pfs_ino dir_ino, const char* name, uint32_t* child_ino, uint32_t* child_type) {
    struct pfs_dinode di;
    uint8_t* buf; uint64_t size; int r;
    if (!pfs_repack_read_dinode(pfs, map, dir_ino, &di))
      return 0;
    size = LE64(di.size);
    buf = (uint8_t*)malloc((size_t)(size ? size : 1));
    if (!buf)
      return 0;
    if (!pfs_repack_read_content(pfs, map, &di, buf, size)) { free(buf); return 0; }
    r = pfs_repack_dir_find(buf, size, name, child_ino, child_type, NULL, NULL);
    free(buf);
    return r;
  }

  /* Resolve a '/'- or '\\'-separated relative path from the user root, via map.
     Empty path resolves to the user root. Returns 1 if found. */
  static int pfs_repack_lookup_path(struct pfs* pfs, struct file_map* map, const char* rel, uint32_t* out_ino, uint32_t* out_type) {
    char comp[PATH_MAX];
    const char* p = rel;
    uint32_t ino = (uint32_t)pfs->user_root_dir_ino;
    uint32_t type = PFS_ENTRY_DIRECTORY;
    while (*p == '/' || *p == '\\') ++p;
    while (*p) {
      size_t n = 0;
      while (p[n] && p[n] != '/' && p[n] != '\\') ++n;
      if (n == 0 || n >= sizeof(comp)) return 0;
      memcpy(comp, p, n); comp[n] = 0;
      if (!pfs_repack_lookup_child(pfs, map, ino, comp, &ino, &type)) return 0;
      p += n;
      while (*p == '/' || *p == '\\') ++p;
    }
    if (out_ino) *out_ino = ino;
    if (out_type) *out_type = type;
    return 1;
  }

  /* Allocate a SAFE inode: ino_bitmap bit==0 AND its dinode empty (mode==0 &&
     block_count==0). The backup-generation skew makes the bitmap alone
     unreliable both ways (see ps4-savedata-pfs-allocator-format). Sets the bit;
     returns 0 on exhaustion (inode 0 is the super root, so 0 = sentinel). */
  static uint32_t pfs_repack_meta_alloc_inode(struct pfs* pfs, struct pfs_repack_mod_ctx* ctx, struct file_map* map) {
    uint64_t total, ino;
    if (!ctx->ino_bitmap)
      return 0;
    total = ctx->ino_bitmap_size * 8;
    if (LE64(pfs->hdr.dinode_count) < total)
      total = LE64(pfs->hdr.dinode_count);
    for (ino = 1; ino < total; ++ino) {
      struct pfs_dinode di;
      if (ctx->ino_bitmap[ino / 8] & (uint8_t)(1u << (ino % 8)))
        continue;                                         /* bitmap: used */
      if (!pfs_repack_read_dinode(pfs, map, (pfs_ino)ino, &di))
        continue;                                         /* in indirect dinode block */
      if (LE16(di.mode) != 0 || LE32(di.sdi32.block_count) != 0)
        continue;                                         /* live dinode (backup-gen) */
      ctx->ino_bitmap[ino / 8] |= (uint8_t)(1u << (ino % 8));
      ctx->meta_dirty = 1;
      return (uint32_t)ino;
    }
    return 0;
  }

  static void pfs_repack_meta_free_inode(struct pfs_repack_mod_ctx* ctx, uint32_t ino) {
    if (ctx->ino_bitmap && (ino / 8) < ctx->ino_bitmap_size)
      ctx->ino_bitmap[ino / 8] &= (uint8_t)~(1u << (ino % 8));
    ctx->meta_dirty = 1;
  }

  /* General content writer: set inode `ino`'s data to `content` (content_size
     bytes), (re)allocating or freeing data + indirect blocks to match, writing
     `meta_in` as the dinode (size/block_count/pointers filled here), and
     re-signing the Merkle path to the super root. Old blocks come from the
     current dinode in map; a zeroed/empty current dinode means brand-new.
     Single-level indirect only. (Unifies grow/shrink/patch for the new paths.) */
  static int pfs_repack_put_content(struct pfs* pfs, struct pfs_repack_mod_ctx* ctx, struct file_map* map, pfs_ino ino, const struct pfs_dinode* meta_in, const uint8_t* content, uint64_t content_size) {
    size_t bbs = pfs->basic_block_size;
    struct pfs_dinode dinode, old;
    uint64_t* oldblocks = NULL; uint64_t old_count = 0, old_ind_block = 0;
    uint64_t* newphys = NULL;
    uint8_t* plain = NULL; uint8_t* indbuf = NULL; uint8_t* dblock = NULL;
    uint64_t new_count, i, ind_block_no = 0;
    uint64_t dinode_block_no; size_t dinode_off, idx1;
    uint8_t digest[PFS_HASH_SIZE];
    int old_ind, new_ind;
    int status = 0;

    memcpy(&dinode, meta_in, sizeof(dinode));

    if (pfs_repack_read_dinode(pfs, map, ino, &old) && (LE16(old.mode) != 0 || LE32(old.sdi32.block_count) != 0)) {
      oldblocks = pfs_repack_collect_blocks(pfs, map, &old, &old_count, &old_ind_block);
      if (!oldblocks && old_count) goto error;
    }
    old_ind = old_count > (uint64_t)PFS_DIRECT_BLOCK_MAX_COUNT;

    new_count = content_size == 0 ? 0 : (content_size + bbs - 1) / bbs;
    new_ind = new_count > (uint64_t)PFS_DIRECT_BLOCK_MAX_COUNT;

    if (new_count > (uint64_t)PFS_DIRECT_BLOCK_MAX_COUNT + pfs->indirect_ptrs_per_block) {
      warning("Inode %" PRIuMAX " too large (multi-level indirect not supported).", (uintmax_t)ino);
      goto error;
    }
    if (!pfs_repack_dinode_loc(pfs, ino, &dinode_block_no, &dinode_off)) {
      warning("Inode %" PRIuMAX " lives in an indirect super-root dinode block (unsupported).", (uintmax_t)ino);
      goto error;
    }

    if (new_count) {
      newphys = (uint64_t*)malloc((size_t)new_count * sizeof(uint64_t));
      plain = (uint8_t*)malloc(bbs);
      if (!newphys || !plain) goto error;
    }

    for (i = 0; i < new_count && i < old_count; ++i)
      newphys[i] = oldblocks[i];

    if (new_ind) {
      if (old_ind) {
        ind_block_no = old_ind_block;
      } else {
        ind_block_no = pfs_repack_meta_alloc_block(ctx, (uint32_t)ino);
        if (!ind_block_no) { warning("No free block for indirect (ino %" PRIuMAX ").", (uintmax_t)ino); goto error; }
      }
    }
    for (i = old_count; i < new_count; ++i) {
      uint32_t bat = (i < (uint64_t)PFS_DIRECT_BLOCK_MAX_COUNT) ? (uint32_t)ino : (0x80000000u | (uint32_t)ind_block_no);
      uint64_t phys = pfs_repack_meta_alloc_block(ctx, bat);
      if (!phys) { warning("No free blocks to write ino %" PRIuMAX " (need %" PRIuMAX " more).", (uintmax_t)ino, (uintmax_t)(new_count - i)); goto error; }
      newphys[i] = phys;
    }

    if (new_ind) { indbuf = (uint8_t*)malloc(bbs); if (!indbuf) goto error; memset(indbuf, 0, bbs); }

    memset(dinode.sdi32.direct_blocks, 0, sizeof(dinode.sdi32.direct_blocks));
    memset(dinode.sdi32.indirect_blocks, 0, sizeof(dinode.sdi32.indirect_blocks));

    for (i = 0; i < new_count; ++i) {
      uint64_t off = i * bbs;
      uint64_t csz = (content_size - off > bbs) ? bbs : (content_size - off);
      memset(plain, 0, bbs);
      memcpy(plain, content + off, (size_t)csz);
      if (!pfs_repack_write_block(pfs, map, newphys[i], plain, digest)) goto error;
      if (i < (uint64_t)PFS_DIRECT_BLOCK_MAX_COUNT) {
        memcpy(dinode.sdi32.direct_blocks[i].digest, digest, PFS_HASH_SIZE);
        dinode.sdi32.direct_blocks[i].block_no = LE32((uint32_t)newphys[i]);
      } else {
        struct pfs_sblock32* ent = (struct pfs_sblock32*)(indbuf + (size_t)(i - PFS_DIRECT_BLOCK_MAX_COUNT) * pfs->block_info_struct_size);
        memcpy(ent->digest, digest, PFS_HASH_SIZE);
        ent->block_no = LE32((uint32_t)newphys[i]);
      }
    }
    if (new_ind) {
      if (!pfs_repack_write_block(pfs, map, ind_block_no, indbuf, digest)) goto error;
      memcpy(dinode.sdi32.indirect_blocks[0].digest, digest, PFS_HASH_SIZE);
      dinode.sdi32.indirect_blocks[0].block_no = LE32((uint32_t)ind_block_no);
    }

    /* Free old blocks no longer used. */
    for (i = new_count; i < old_count; ++i)
      pfs_repack_meta_free_block(ctx, oldblocks[i]);
    if (old_ind && !new_ind)
      pfs_repack_meta_free_block(ctx, old_ind_block);

    dinode.size = LE64(content_size);
    dinode.size_uncompressed = LE64(content_size);
    dinode.sdi32.block_count = LE32((uint32_t)new_count);

    dblock = (uint8_t*)malloc(bbs);
    if (!dblock) goto error;
    pfs_repack_read_out_block(pfs, map, dinode_block_no, dblock);
    memcpy(dblock + dinode_off, &dinode, pfs->dinode_struct_size);
    if (!pfs_repack_write_block(pfs, map, dinode_block_no, dblock, digest)) goto error;

    idx1 = (size_t)(ino / pfs->inodes_per_block);
    memcpy(pfs->hdr.super_root_dinode.sdi64.direct_blocks[idx1].digest, digest, PFS_HASH_SIZE);

    status = 1;
  error:
    free(oldblocks); free(newphys); free(plain); free(indbuf); free(dblock);
    return status;
  }

  /* Free an inode's data (blocks + indirect) and zero its dinode. */
  static int pfs_repack_free_inode_data(struct pfs* pfs, struct pfs_repack_mod_ctx* ctx, struct file_map* map, pfs_ino ino) {
    struct pfs_dinode zero;
    memset(&zero, 0, sizeof(zero));
    return pfs_repack_put_content(pfs, ctx, map, ino, &zero, NULL, 0);
  }

  /* Insert a dirent into directory dir_ino (content read from + written back to
     map), growing the dir by a block if it doesn't fit. link_delta adjusts the
     dir's link_count (+1 when adding a subdirectory). */
  static int pfs_repack_dir_insert(struct pfs* pfs, struct pfs_repack_mod_ctx* ctx, struct file_map* map, pfs_ino dir_ino, const char* name, uint32_t child_ino, uint32_t child_type, int link_delta) {
    size_t bbs = pfs->basic_block_size;
    struct pfs_dinode di;
    uint8_t* buf = NULL; uint64_t size, cap, p, new_used, new_size;
    size_t nlen = strlen(name);
    uint32_t es = (uint32_t)align_up(16 + nlen + 1, 8);
    struct pfs_dir_entry* e;
    int status = 0;

    if (!pfs_repack_read_dinode(pfs, map, dir_ino, &di)) goto error;
    size = LE64(di.size);
    cap = size + bbs;                                    /* room to grow by 1 block */
    buf = (uint8_t*)calloc(1, (size_t)cap);
    if (!buf) goto error;
    if (!pfs_repack_read_content(pfs, map, &di, buf, size)) goto error;

    if (pfs_repack_dir_find(buf, size, name, NULL, NULL, NULL, NULL)) {
      warning("Entry '%s' already exists; not adding.", name);
      goto error;
    }

    p = 0;
    while (p + PFS_MIN_DIR_ENTRY_SIZE <= size) {
      struct pfs_dir_entry* ent = (struct pfs_dir_entry*)(buf + p);
      if (LE32(ent->ino) == 0 || LE32(ent->entry_size) == 0) break;
      p += LE32(ent->entry_size);
    }
    new_used = p + es;
    new_size = size;
    if (new_used + 16 > size) {                          /* keep a zero terminator */
      new_size = align_up(new_used + 16, bbs);
      if (new_size > cap) { warning("Directory entry too large to fit."); goto error; }
    }
    e = (struct pfs_dir_entry*)(buf + p);
    e->ino = LE32(child_ino);
    e->type = LE32(child_type);
    e->name_size = LE32((uint32_t)nlen);
    e->entry_size = LE32(es);
    memset(e->name, 0, es - 16);
    memcpy(e->name, name, nlen);

    di.link_count = LE16((uint16_t)(LE16(di.link_count) + link_delta));
    if (!pfs_repack_put_content(pfs, ctx, map, dir_ino, &di, buf, new_size)) goto error;
    status = 1;
  error:
    free(buf);
    return status;
  }

  /* Remove dirent `name` from directory dir_ino (compact tail, keep same size).
     link_delta adjusts link_count (-1 when removing a subdirectory). */
  static int pfs_repack_dir_remove_entry(struct pfs* pfs, struct pfs_repack_mod_ctx* ctx, struct file_map* map, pfs_ino dir_ino, const char* name, int link_delta) {
    struct pfs_dinode di;
    uint8_t* buf = NULL; uint64_t size, off; uint32_t es;
    int status = 0;
    if (!pfs_repack_read_dinode(pfs, map, dir_ino, &di)) goto error;
    size = LE64(di.size);
    buf = (uint8_t*)calloc(1, (size_t)(size ? size : 1));
    if (!buf) goto error;
    if (!pfs_repack_read_content(pfs, map, &di, buf, size)) goto error;
    if (!pfs_repack_dir_find(buf, size, name, NULL, NULL, &off, &es)) {
      warning("Entry '%s' not found for removal.", name);
      goto error;
    }
    memmove(buf + off, buf + off + es, (size_t)(size - off - es));
    memset(buf + size - es, 0, (size_t)es);
    di.link_count = LE16((uint16_t)(LE16(di.link_count) + link_delta));
    if (!pfs_repack_put_content(pfs, ctx, map, dir_ino, &di, buf, size)) goto error;
    status = 1;
  error:
    free(buf);
    return status;
  }

  /* Add a regular file `name` under parent_ino with the given content. */
  static int pfs_repack_add_file(struct pfs* pfs, struct pfs_repack_mod_ctx* ctx, struct file_map* map, pfs_ino parent_ino, const char* name, const struct pfs_dinode* tmpl, const uint8_t* data, uint64_t size) {
    struct pfs_dinode di;
    uint32_t ino = pfs_repack_meta_alloc_inode(pfs, ctx, map);
    if (!ino) { warning("No free inode to add '%s'.", name); return 0; }
    memcpy(&di, tmpl, sizeof(di));
    di.link_count = LE16(1);
    if (!pfs_repack_put_content(pfs, ctx, map, ino, &di, data, size)) return 0;
    if (!pfs_repack_dir_insert(pfs, ctx, map, parent_ino, name, ino, PFS_ENTRY_FILE, 0)) return 0;
    return 1;
  }

  /* Add an (empty) directory `name` under parent_ino; one block, "."/".." set. */
  static int pfs_repack_add_dir(struct pfs* pfs, struct pfs_repack_mod_ctx* ctx, struct file_map* map, pfs_ino parent_ino, const char* name, const struct pfs_dinode* dtmpl, uint32_t* out_ino) {
    size_t bbs = pfs->basic_block_size;
    struct pfs_dinode di;
    uint8_t* buf = NULL;
    struct pfs_dir_entry* e;
    uint32_t ino = pfs_repack_meta_alloc_inode(pfs, ctx, map);
    int status = 0;
    if (!ino) { warning("No free inode to add dir '%s'.", name); return 0; }
    memcpy(&di, dtmpl, sizeof(di));
    di.link_count = LE16(2);
    buf = (uint8_t*)calloc(1, bbs);
    if (!buf) return 0;
    e = (struct pfs_dir_entry*)buf;                       /* "." -> self */
    e->ino = LE32(ino); e->type = LE32(PFS_ENTRY_THIS); e->name_size = LE32(1); e->entry_size = LE32(24);
    e->name[0] = '.';
    e = (struct pfs_dir_entry*)(buf + 24);                /* ".." -> parent */
    e->ino = LE32((uint32_t)parent_ino); e->type = LE32(PFS_ENTRY_PARENT); e->name_size = LE32(2); e->entry_size = LE32(24);
    e->name[0] = '.'; e->name[1] = '.';
    if (!pfs_repack_put_content(pfs, ctx, map, ino, &di, buf, bbs)) goto error;
    if (!pfs_repack_dir_insert(pfs, ctx, map, parent_ino, name, ino, PFS_ENTRY_DIRECTORY, +1)) goto error;
    if (out_ino) *out_ino = ino;
    status = 1;
  error:
    free(buf);
    return status;
  }

  /* Recursively free a directory's children (data + inodes + ino_bitmap bits).
     Does not touch the directory's own content (it is being removed). */
  static int pfs_repack_free_dir_recursive(struct pfs* pfs, struct pfs_repack_mod_ctx* ctx, struct file_map* map, pfs_ino dir_ino) {
    struct pfs_dinode di;
    uint8_t* buf = NULL; uint64_t size, p;
    int status = 0;
    if (!pfs_repack_read_dinode(pfs, map, dir_ino, &di)) goto error;
    size = LE64(di.size);
    buf = (uint8_t*)calloc(1, (size_t)(size ? size : 1));
    if (!buf) goto error;
    if (!pfs_repack_read_content(pfs, map, &di, buf, size)) goto error;
    p = 0;
    while (p + PFS_MIN_DIR_ENTRY_SIZE <= size) {
      struct pfs_dir_entry* e = (struct pfs_dir_entry*)(buf + p);
      uint32_t cino = LE32(e->ino), es = LE32(e->entry_size), ctype = LE32(e->type);
      if (cino == 0 || es == 0) break;
      if (ctype != PFS_ENTRY_THIS && ctype != PFS_ENTRY_PARENT) {
        if (ctype == PFS_ENTRY_DIRECTORY) {
          if (!pfs_repack_free_dir_recursive(pfs, ctx, map, cino)) goto error;
        }
        if (!pfs_repack_free_inode_data(pfs, ctx, map, cino)) goto error;
        pfs_repack_meta_free_inode(ctx, cino);
      }
      p += es;
    }
    status = 1;
  error:
    free(buf);
    return status;
  }

  /* Remove a file or (recursively) a directory at relative path `rel`. */
  static int pfs_repack_remove_path(struct pfs* pfs, struct pfs_repack_mod_ctx* ctx, struct file_map* map, const char* rel) {
    char prel[PATH_MAX]; const char* child; char* slash;
    uint32_t parent_ino, child_ino, child_type;
    int link_delta = 0;

    strncpy(prel, rel, sizeof(prel)); prel[sizeof(prel) - 1] = 0;
    /* strip trailing separators */
    { size_t l = strlen(prel); while (l && (prel[l-1]=='/'||prel[l-1]=='\\')) prel[--l] = 0; }
    slash = strrchr(prel, '/');
    { char* b = strrchr(prel, '\\'); if (b && (!slash || b > slash)) slash = b; }
    if (slash) { *slash = 0; child = slash + 1; }
    else { child = prel; }

    if (slash) {
      if (!pfs_repack_lookup_path(pfs, map, prel, &parent_ino, NULL)) { warning("Parent of '%s' not found.", rel); return 0; }
    } else {
      parent_ino = (uint32_t)pfs->user_root_dir_ino;
    }
    if (!pfs_repack_lookup_child(pfs, map, parent_ino, child, &child_ino, &child_type)) {
      warning("Path '%s' not found; nothing to remove.", rel);
      return 0;
    }
    if (child_type == PFS_ENTRY_DIRECTORY) {
      if (!pfs_repack_free_dir_recursive(pfs, ctx, map, child_ino)) return 0;
      link_delta = -1;
    }
    if (!pfs_repack_free_inode_data(pfs, ctx, map, child_ino)) return 0;
    pfs_repack_meta_free_inode(ctx, child_ino);
    if (!pfs_repack_dir_remove_entry(pfs, ctx, map, parent_ino, child, link_delta)) return 0;
    return 1;
  }

  /* Read __remove.txt (one relative path per line; '#' comments) and apply. */
  static void pfs_repack_run_removes(struct pfs* pfs, struct pfs_repack_mod_ctx* ctx, struct file_map* map, const char* mod_dir) {
    char path[PATH_MAX]; char line[PATH_MAX]; FILE* fp;
    uint32_t ino;
    snprintf(path, sizeof(path), "%s/__remove.txt", mod_dir);
    if (!is_file(path)) return;
    fp = fopen(path, "r");
    if (!fp) { warning("Unable to open %s.", path); return; }
    while (fgets(line, sizeof(line), fp)) {
      size_t l = strlen(line);
      while (l && (line[l-1]=='\n'||line[l-1]=='\r'||line[l-1]==' '||line[l-1]=='\t')) line[--l] = 0;
      { char* s = line; while (*s==' '||*s=='\t') ++s; if (s != line) memmove(line, s, strlen(s)+1); }
      if (line[0] == 0 || line[0] == '#') continue;
      if (!pfs_repack_lookup_path(pfs, map, line, &ino, NULL)) {
        warning("Remove: '%s' not present; skipping.", line);
        continue;
      }
      info("Removing: %s", line);
      if (!pfs_repack_remove_path(pfs, ctx, map, line)) { ctx->error = 1; break; }
      ctx->changed++;
    }
    fclose(fp);
  }

  struct pfs_repack_find_file_args { pfs_ino ino; int found; };
  static enum cb_result pfs_repack_find_file_cb(void* arg, struct pfs* pfs, pfs_ino ino, enum pfs_entry_type type, const char* path, uint64_t size, uint32_t flags) {
    struct pfs_repack_find_file_args* a = (struct pfs_repack_find_file_args*)arg;
    UNUSED(pfs); UNUSED(path); UNUSED(size);
    if (type == PFS_ENTRY_FILE && !(flags & PFS_FILE_COMPRESSED)) { a->ino = ino; a->found = 1; return CB_RESULT_STOP; }
    return CB_RESULT_CONTINUE;
  }

#define PFS_REPACK_MAX_REMOVES 256
  struct pfs_repack_add_cb_args {
    struct pfs* pfs; struct pfs_repack_mod_ctx* ctx; struct file_map* map;
    size_t mod_dir_len;
    struct pfs_dinode ftmpl, dtmpl;
    char removed[PFS_REPACK_MAX_REMOVES][256]; /* normalized manifest paths to not re-add */
    int removed_count;
  };
  /* Normalize a relative path in place: '\\' -> '/', strip leading/trailing '/'. */
  static void pfs_repack_normrel(char* s) {
    char* w = s; char* r = s; size_t l;
    while (*r == '/' || *r == '\\') ++r;
    while (*r) { *w++ = (*r == '\\') ? '/' : *r; ++r; }
    *w = 0;
    l = strlen(s);
    while (l && s[l-1] == '/') s[--l] = 0;
  }
  static int pfs_repack_add_cb(void* arg, const char* parent, const char* child, unsigned int mode) {
    struct pfs_repack_add_cb_args* a = (struct pfs_repack_add_cb_args*)arg;
    char full[PATH_MAX]; char prel[PATH_MAX]; char norm[PATH_MAX];
    const char* rel; char* slash;
    uint32_t ino, type, parent_ino;
    int i;

    snprintf(full, sizeof(full), "%s/%s", parent, child);
    rel = full + a->mod_dir_len;
    while (*rel == '/' || *rel == '\\') ++rel;

    if (strcmp(rel, "__remove.txt") == 0) return CB_RESULT_CONTINUE;
    /* Don't re-add anything the manifest removed (removals win). */
    strncpy(norm, rel, sizeof(norm)); norm[sizeof(norm)-1] = 0; pfs_repack_normrel(norm);
    for (i = 0; i < a->removed_count; ++i)
      if (strcmp(norm, a->removed[i]) == 0) return CB_RESULT_CONTINUE;
    if (pfs_repack_lookup_path(a->pfs, a->map, rel, &ino, &type)) return CB_RESULT_CONTINUE; /* already present */

    strncpy(prel, rel, sizeof(prel)); prel[sizeof(prel) - 1] = 0;
    slash = strrchr(prel, '/');
    { char* b = strrchr(prel, '\\'); if (b && (!slash || b > slash)) slash = b; }
    if (slash) *slash = 0; else prel[0] = 0;
    if (!pfs_repack_lookup_path(a->pfs, a->map, prel, &parent_ino, &type)) {
      warning("Parent of '%s' not found; skipping.", rel);
      return CB_RESULT_CONTINUE;
    }

    if (S_ISDIR(mode)) {
      if (!pfs_repack_add_dir(a->pfs, a->ctx, a->map, parent_ino, child, &a->dtmpl, NULL)) { a->ctx->error = 1; return CB_RESULT_STOP; }
      info("Added directory: %s", rel);
      a->ctx->changed++;
    } else {
      uint64_t sz = get_file_size(full);
      uint8_t* data = (uint8_t*)malloc(sz ? (size_t)sz : 1);
      FILE* fp;
      if (!data) { a->ctx->error = 1; return CB_RESULT_STOP; }
      fp = fopen(full, "rb");
      if (!fp || (sz && fread(data, 1, (size_t)sz, fp) != sz)) {
        warning("Unable to read '%s'.", full);
        if (fp) fclose(fp);
        free(data); a->ctx->error = 1; return CB_RESULT_STOP;
      }
      fclose(fp);
      if (!pfs_repack_add_file(a->pfs, a->ctx, a->map, parent_ino, child, &a->ftmpl, data, sz)) { free(data); a->ctx->error = 1; return CB_RESULT_STOP; }
      free(data);
      info("Added file: %s (%" PRIuMAX " bytes)", rel, (uintmax_t)sz);
      a->ctx->changed++;
    }
    return CB_RESULT_CONTINUE;
  }

  /* Walk mod_dir; add every file/dir not already present in the image. */
  static void pfs_repack_run_adds(struct pfs* pfs, struct pfs_repack_mod_ctx* ctx, struct file_map* map, const char* mod_dir) {
    struct pfs_repack_add_cb_args a;
    struct pfs_repack_find_file_args ff;
    memset(&a, 0, sizeof(a));
    a.pfs = pfs; a.ctx = ctx; a.map = map;
    a.mod_dir_len = strlen(mod_dir);
    if (!ctx->ino_bitmap) { return; } /* no inode allocator -> nothing to add */

    /* Load __remove.txt paths so the walk never re-adds a removed entry. */
    {
      char path[PATH_MAX]; char line[PATH_MAX]; FILE* fp;
      snprintf(path, sizeof(path), "%s/__remove.txt", mod_dir);
      fp = fopen(path, "r");
      if (fp) {
        while (fgets(line, sizeof(line), fp) && a.removed_count < PFS_REPACK_MAX_REMOVES) {
          size_t l = strlen(line);
          while (l && (line[l-1]=='\n'||line[l-1]=='\r'||line[l-1]==' '||line[l-1]=='\t')) line[--l] = 0;
          { char* s = line; while (*s==' '||*s=='\t') ++s; if (s != line) memmove(line, s, strlen(s)+1); }
          if (line[0] == 0 || line[0] == '#') continue;
          pfs_repack_normrel(line);
          strncpy(a.removed[a.removed_count], line, sizeof(a.removed[0])); a.removed[a.removed_count][sizeof(a.removed[0])-1] = 0;
          ++a.removed_count;
        }
        fclose(fp);
      }
    }

    if (!pfs_get_dinode(pfs, pfs->user_root_dir_ino, &a.dtmpl, NULL, NULL)) {
      warning("No directory template available; cannot add entries.");
      return;
    }
    ff.found = 0;
    pfs_enum_user_root_directory(pfs, &pfs_repack_find_file_cb, &ff);
    if (!(ff.found && pfs_get_dinode(pfs, ff.ino, &a.ftmpl, NULL, NULL))) {
      /* derive a file template from the directory template */
      memcpy(&a.ftmpl, &a.dtmpl, sizeof(a.ftmpl));
      a.ftmpl.mode = LE16((uint16_t)((LE16(a.dtmpl.mode) & PFS_FILE_PERMS_MASK) | PFS_FILE_TYPE_REG));
      a.ftmpl.flags = LE32(0);
    }
    list_directory_r(mod_dir, &pfs_repack_add_cb, &a);
  }

  static enum cb_result pfs_repack_mod_enum_cb(void* arg, struct pfs* pfs, pfs_ino ino, enum pfs_entry_type type, const char* path, uint64_t size, uint32_t flags) {
    struct pfs_repack_mod_ctx* ctx = (struct pfs_repack_mod_ctx*)arg;
    char fs_path[PATH_MAX];
    const char* rel;
    uint8_t* new_data = NULL;
    uint8_t* cur_data = NULL;
    struct pfs_file_context* file = NULL;
    uint64_t disk_size;
    FILE* fp = NULL;

    UNUSED(flags);

    if (type != PFS_ENTRY_FILE)
      return CB_RESULT_CONTINUE;

    rel = (path[0] == '/' || path[0] == '\\') ? path + 1 : path;
    snprintf(fs_path, sizeof(fs_path), "%s/%s", ctx->mod_dir, rel);

    if (!is_file(fs_path))
      return CB_RESULT_CONTINUE; /* not provided -> keep original */

    disk_size = get_file_size(fs_path);

    new_data = (uint8_t*)malloc(disk_size ? (size_t)disk_size : 1);
    cur_data = (uint8_t*)malloc(size ? (size_t)size : 1);
    if (!new_data || !cur_data) {
      ctx->error = 1;
      goto done;
    }

    fp = fopen(fs_path, "rb");
    if (!fp || (disk_size > 0 && fread(new_data, 1, (size_t)disk_size, fp) != disk_size)) {
      warning("Unable to read '%s'.", fs_path);
      ctx->error = 1;
      goto done;
    }
    fclose(fp);
    fp = NULL;

    if (disk_size > size) {
      /* Grow: more bytes than the image file -> allocate extra blocks. */
      info("Growing file: %s (%" PRIuMAX " -> %" PRIuMAX " bytes)", rel, (uintmax_t)size, (uintmax_t)disk_size);
      if (!pfs_repack_grow_file(pfs, ctx, ino, new_data, disk_size)) {
        ctx->error = 1;
        goto done;
      }
      ctx->changed++;
      goto done;
    }

    if (disk_size < size) {
      /* Shrink: fewer bytes than the image file -> free tail blocks. */
      info("Shrinking file: %s (%" PRIuMAX " -> %" PRIuMAX " bytes)", rel, (uintmax_t)size, (uintmax_t)disk_size);
      if (!pfs_repack_shrink_file(pfs, ctx, ino, new_data, disk_size)) {
        ctx->error = 1;
        goto done;
      }
      ctx->changed++;
      goto done;
    }

    /* Same size: compare against current image content to skip unchanged files. */
    file = pfs_get_file(pfs, ino);
    if (file && size > 0) {
      if (!pfs_file_read(file, 0, cur_data, size)) {
        warning("Unable to read current content of '%s'.", rel);
        ctx->error = 1;
        goto done;
      }
    }
    pfs_free_file(file);
    file = NULL;

    if (size > 0 && memcmp(new_data, cur_data, (size_t)size) == 0)
      goto done; /* unchanged */

    info("Repacking modified file: %s", rel);
    if (!pfs_repack_patch_file(pfs, ctx->map, ino, new_data, size)) {
      ctx->error = 1;
      goto done;
    }
    ctx->changed++;

done:
    if (fp)
      fclose(fp);
    if (file)
      pfs_free_file(file);
    if (new_data)
      free(new_data);
    if (cur_data)
      free(cur_data);

    return ctx->error ? CB_RESULT_STOP : CB_RESULT_CONTINUE;
  }

  static int pfs_repack_apply_mods(struct pfs* pfs, struct file_map* map, const char* mod_dir) {
    struct pfs_repack_mod_ctx ctx;
    uint8_t* hbuf = NULL;
    unsigned int key_ver = 0;
    int status = 0;

    memset(&ctx, 0, sizeof(ctx));
    ctx.pfs = pfs;
    ctx.map = map;
    ctx.mod_dir = mod_dir;

    /* Load decrypted blk_bitmap + BAT so resize can free/allocate blocks.
       Only meaningful for signed SD PFS; absence just disables resize. */
    if (pfs->format == PFS_FORMAT_32_SIGNED && pfs->block_bitmap_ino > 0 && pfs->block_addr_table_ino > 0) {
      struct pfs_file_context* bf = pfs_get_file(pfs, pfs->block_bitmap_ino);
      struct pfs_file_context* af = pfs_get_file(pfs, pfs->block_addr_table_ino);
      if (bf && af && bf->file_size > 0 && af->file_size > 0) {
        ctx.bitmap = (uint8_t*)malloc((size_t)bf->file_size);
        ctx.bat = (uint8_t*)malloc((size_t)af->file_size);
        if (ctx.bitmap && ctx.bat &&
            pfs_file_read(bf, 0, ctx.bitmap, bf->file_size) &&
            pfs_file_read(af, 0, ctx.bat, af->file_size)) {
          ctx.bitmap_size = bf->file_size;
          ctx.bat_size = af->file_size;
          ctx.meta_loaded = 1;
        }
      }
      if (bf) pfs_free_file(bf);
      if (af) pfs_free_file(af);

      /* ino_bitmap too, so add/remove can allocate/free inodes. */
      if (pfs->ino_bitmap_ino > 0) {
        struct pfs_file_context* nf = pfs_get_file(pfs, pfs->ino_bitmap_ino);
        if (nf && nf->file_size > 0) {
          ctx.ino_bitmap = (uint8_t*)malloc((size_t)nf->file_size);
          if (ctx.ino_bitmap && pfs_file_read(nf, 0, ctx.ino_bitmap, nf->file_size))
            ctx.ino_bitmap_size = nf->file_size;
          else { free(ctx.ino_bitmap); ctx.ino_bitmap = NULL; }
        }
        if (nf) pfs_free_file(nf);
      }
    }

    /* 1) Same-path modifications (grow/shrink/patch) over the image tree. */
    if (!pfs_enum_user_root_directory(pfs, &pfs_repack_mod_enum_cb, &ctx)) {
      warning("Unable to enumerate files for modification.");
      goto error;
    }
    if (ctx.error)
      goto error;

    /* 2) Removals from the __remove.txt manifest, then 3) additions (any file
       or directory present in mod_dir but not in the image). Removals first so
       freed blocks/inodes can be reused by additions. */
    pfs_repack_run_removes(pfs, &ctx, map, mod_dir);
    if (ctx.error)
      goto error;
    pfs_repack_run_adds(pfs, &ctx, map, mod_dir);
    if (ctx.error)
      goto error;

    if (ctx.changed == 0) {
      info("No modified files found in '%s'; output is a verbatim copy of the source image.", mod_dir);
      status = 1;
      goto error;
    }

    /*
     * Flush the edited allocator metadata (blk_bitmap + BAT) back into their
     * own (same-size) files and re-sign their Merkle paths to the super root.
     * Must happen before the header is re-signed below.
     */
    if (ctx.meta_dirty) {
      if (!pfs_repack_patch_file(pfs, map, pfs->block_bitmap_ino, ctx.bitmap, ctx.bitmap_size)) {
        warning("Unable to re-sign modified blk_bitmap.");
        goto error;
      }
      if (!pfs_repack_patch_file(pfs, map, pfs->block_addr_table_ino, ctx.bat, ctx.bat_size)) {
        warning("Unable to re-sign modified BAT.");
        goto error;
      }
      if (ctx.ino_bitmap && !pfs_repack_patch_file(pfs, map, pfs->ino_bitmap_ino, ctx.ino_bitmap, ctx.ino_bitmap_size)) {
        warning("Unable to re-sign modified ino_bitmap.");
        goto error;
      }
    }

    /*
     * Re-sign the header. The super_root_dinode digests were updated in pfs->hdr
     * (in memory) by pfs_repack_patch_file. Only the header's first 0x380 bytes
     * are covered by header_hash and are plaintext; info_data (0x3A0..) stays as
     * the original encrypted bytes already present in the output copy.
     */
    hbuf = (uint8_t*)malloc(PFS_HEADER_SIZE);
    if (!hbuf)
      goto error;
    memset(hbuf, 0, PFS_HEADER_SIZE);
    memcpy(hbuf, &pfs->hdr, PFS_HEADER_COVER_SIZE_FOR_ICV);
    pfs_sign_buffer(pfs, hbuf, PFS_HEADER_SIZE, pfs->hdr.header_hash);

    /* Write header[0:0x380] (main fields, updated super root) + header_hash into the output. */
    memcpy(map->data, &pfs->hdr, PFS_HEADER_COVER_SIZE_FOR_ICV);
    memcpy(map->data + PFS_HEADER_COVER_SIZE_FOR_ICV, pfs->hdr.header_hash, PFS_HASH_SIZE);

#if defined(ENABLE_SD_KEYGEN)
    /* SD bottom signature: HMAC(sd_hdr_sig_key, header[0:0x580]) — enforced when sd_key_ver > 2. */
    if (pfs_get_sd_key_ver(pfs, &key_ver) && key_ver > 2) {
      if (!g_sd_hdr_sig_key) {
        warning("SD header signature key not found; cannot re-sign modified image.");
        goto error;
      }
      hmac_sha256_buffer(g_sd_hdr_sig_key, KEYMGR_SD_HEADER_SIG_KEY_SIZE, map->data, PFS_SD_HEADER_SIZE, map->data + PFS_SD_HEADER_SIZE);
    }

    /*
     * SD auth code (offset 0x7F90) carries a copy of the header hash (pfs_hdr_hash1),
     * AES-CBC-CTS encrypted with the SD auth-code key. Update it to the new header
     * hash so it stays consistent. The copy counter and pfs_hdr_hash2 are preserved.
     */
    {
      const uint64_t ac_magic = SD_AUTH_CODE_MAGIC;
      struct sd_auth_code ac;
      memcpy(&ac, map->data + SD_AUTH_CODE_OFFSET, sizeof(ac));
      if (has_magic((uint8_t*)&ac.magic, sizeof(ac.magic), &ac_magic, sizeof(ac_magic))) {
        if (g_sd_auth_code_key) {
          uint8_t iv_dec[0x10], iv_enc[0x10];
          memcpy(iv_dec, ac.iv, sizeof(iv_dec));
          memcpy(iv_enc, ac.iv, sizeof(iv_enc));
          aes_decrypt_cbc_cts(g_sd_auth_code_key, KEYMGR_SD_AUTH_CODE_KEY_SIZE, iv_dec, ac.data, ac.data, sizeof(ac.data));
          memcpy(ac.info.pfs_hdr_hash1, pfs->hdr.header_hash, PFS_HASH_SIZE);
          aes_encrypt_cbc_cts(g_sd_auth_code_key, KEYMGR_SD_AUTH_CODE_KEY_SIZE, iv_enc, ac.data, ac.data, sizeof(ac.data));
          memcpy(map->data + SD_AUTH_CODE_OFFSET, &ac, sizeof(ac));
        } else {
          warning("SD auth code key not found; header hash in auth code left stale.");
        }
      }
    }
#endif

    info("Repacked %d modified file(s) and re-signed the image header.", ctx.changed);
    warning("SD copy counter left unchanged; verify the result mounts on your console.");

    status = 1;

error:
    if (hbuf)
      free(hbuf);
    if (ctx.bitmap)
      free(ctx.bitmap);
    if (ctx.bat)
      free(ctx.bat);
    if (ctx.ino_bitmap)
      free(ctx.ino_bitmap);

    return status;
  }
#endif

static int process_pkg(cmd_handler_t handler) {
  struct pfs_io_context pfs_ctx;
  struct pfs_io_callbacks pfs_io;
  int ret = 1;

  if (s_pfs_image_data_file) {
    if (!setup_pfs(&pfs_ctx, &pfs_io, s_pfs_image_data_file, 1)) {
      warning("Unable to load PFS file: %s", s_pfs_image_data_file);
      goto error;
    }
  }

  s_pkg = pkg_alloc(s_input_file_path, &set_pkg_pfs_options_cb, NULL);
  if (!s_pkg)
    error("Unable to load PKG file: %s", s_input_file_path);

  if (handler)
    ret = (*handler)(&s_pkg->map->size);
  else
    ret = 1;

error:
  if (s_pfs_image_data_file)
    cleanup_pfs(&pfs_ctx);

  pkg_free(s_pkg);
  s_pkg = NULL;

  return ret;
}

static int pkg_list_handler(void* arg) {
  assert(s_pkg != NULL);

  UNUSED(arg);

  if (!s_pfs_image_data_file) {
    if (!pfs_list_user_root_directory(s_pkg->inner_pfs))
      error("Unable to list entries from PKG file: %s", s_input_file_path);
  } else {
    if (!pfs_list_user_root_directory(s_pfs))
      error("Unable to list entries from PFS file: %s", s_pfs_image_data_file);
  }

  return 0;
}

static enum cb_result pkg_unpack_sc_entries_cb(void* arg, struct pkg* pkg, struct pkg_entry_desc* desc) {
  struct pkg_unpack_sc_entries_cb_args* args = (struct pkg_unpack_sc_entries_cb_args*)arg;
  char file_path[PATH_MAX], directory[PATH_MAX];
  struct pkg_entry_keyset entry_keyset;
  uint8_t* new_data = NULL;
  uint8_t* data;
  uint32_t data_size, data_size_aligned;
  uint64_t data_offset;
  int needed;
  enum cb_result ret = CB_RESULT_CONTINUE;

  assert(args != NULL);
  assert(args->output_directory != NULL);

  assert(pkg != NULL);
  assert(desc != NULL);

  snprintf(file_path, sizeof(file_path), "%s%s", args->output_directory, desc->name);
  path_get_directory(directory, sizeof(directory), file_path);

  data = pkg_locate_entry_data(pkg, desc->id, &data_offset, &data_size);
  if (!data)
    error("Unable to find data for entry '%s'.", desc->name);

  data_size_aligned = align_up_32(data_size, 16);

  if (desc->is_encrypted || desc->use_new_algo) {
    if (!pkg_get_entry_keyset(pkg, desc->id, &entry_keyset)) {
      if (pkg->finalized) { /* could skip some known undecryptable files? */
        switch (desc->id) {
          case PKG_ENTRY_ID__LICENSE_INFO:
            goto done;
          default:
            break;
        }
      }
      warning("Unable to get key for entry '%s', skipping...", desc->name);
      goto done;
    }
  }

  if (args->pre_cb) {
    ret = (*args->pre_cb)(args->pre_cb_arg, file_path, PFS_ENTRY_FILE, &needed);
    if (ret == CB_RESULT_STOP)
      goto done;
    else if (ret == CB_RESULT_CONTINUE && !needed)
      goto done;
  }

  if (*directory != '\0')
    make_directories(directory, 0755);

  new_data = (uint8_t*)malloc(data_size_aligned);
  if (!new_data)
    error("Unable to allocate memory for data of size 0x%08" PRIX32 " bytes for entry '%s'.", data_size_aligned, desc->name);

  memset(new_data, 0, data_size_aligned);
  if (desc->use_new_algo)
    aes_decrypt_oex(entry_keyset.key, sizeof(entry_keyset.key), data_offset, data, new_data, data_size);
  else if (desc->is_encrypted)
    aes_decrypt_cbc_cts(entry_keyset.key, sizeof(entry_keyset.key), entry_keyset.iv, data, new_data, data_size_aligned);
  else
    memcpy(new_data, data, data_size);

  if (!write_to_file(file_path, new_data, data_size, NULL, 0644))
    error("Unable to write file '%s'.", file_path);

done:
  if (new_data)
    free(new_data);

  return ret;
}

static int pkg_create_dummy_shareparam_json(struct pkg* pkg, const char* output_directory, const char* name, int* created) {
  char file_path[PATH_MAX], directory[PATH_MAX];
  struct sfo* sfo = NULL;
  struct sfo_entry* sfo_entry;
  uint8_t* sfo_data;
  uint32_t sfo_data_size;
  char app_ver_str[sizeof("00.00")];
  UT_string* content = NULL;
  int status = 0;

  assert(pkg != NULL);
  assert(output_directory != NULL);
  assert(name != NULL);

  if (created)
    *created = 0;

  sfo_data = pkg_locate_entry_data(pkg, PKG_ENTRY_ID__PARAM_SFO, NULL, &sfo_data_size);
  if (!sfo_data) {
    // No param.sfo (package file is not a game package?).
    goto done;
  }

  sfo = sfo_alloc();
  if (!sfo) {
    warning("Unable to allocate memory for system file object.");
    goto error;
  }
  if (!sfo_load_from_memory(sfo, sfo_data, sfo_data_size)) {
    warning("Unable to load system file object.");
    goto error;
  }

  sfo_entry = sfo_find_entry(sfo, "APP_VER");
  if (sfo_entry) {
    if (sfo_entry->format != SFO_FORMAT_STRING || sfo_entry->size < strlen("00.00") + 1) {
      warning("Invalid format of APP_VER entry in system file object.");
      goto error;
    }
    snprintf(app_ver_str, sizeof(app_ver_str), "%s", (const char*)sfo_entry->value);
  } else {
    snprintf(app_ver_str, sizeof(app_ver_str), "%02u.%02u", 1, 0);
    warning("No APP_VER entry in system file object, using default app version '%s'.", app_ver_str);
  }

  utstring_new(content);
  utstring_printf(content,
    "{\n"
    "\t\"ps4_share_param_version\":\"%02u.%02u\",\n"
    "\t\"game_version\":\"%s\",\n"
#if 0
    "\t\"client\":\"\",\n"
#endif
    "\t\"overlay_position\":{\n"
    "\t\t\"x\":0,\n"
    "\t\t\"y\":0\n"
    "\t}\n"
    "}\n",
    PKG_SHAREPARAM_FILE_VERSION_MAJOR, PKG_SHAREPARAM_FILE_VERSION_MINOR,
    app_ver_str
  );

  snprintf(file_path, sizeof(file_path), "%s%s", output_directory, name);

  path_get_directory(directory, sizeof(directory), file_path);
  if (*directory != '\0')
    make_directories(directory, 0755);

  if (!write_to_file(file_path, utstring_body(content), utstring_len(content), NULL, 0644)) {
    warning("Unable to write file '%s'.", file_path);
    goto error;
  }

  if (created)
    *created = 1;

done:
  status = 1;

error:
  if (content)
    utstring_free(content);
  if (sfo)
    sfo_free(sfo);

  return status;
}

static int pkg_info_handler(void* arg) {
  char output_directory[PATH_MAX];
  struct pkg_unpack_sc_entries_cb_args unpack_sc_entries_args;
  uint8_t* data;
  uint32_t data_size;
  struct sfo* sfo = NULL;
  struct playgo* plgo = NULL;
  int ret = 1;

  assert(s_pkg != NULL);

  UNUSED(arg);

  if (s_unpack_sc_entries) {
    memset(&unpack_sc_entries_args, 0, sizeof(unpack_sc_entries_args));
    {
      snprintf(output_directory, sizeof(output_directory), "%s/Sc0/", s_output_directory);
      unpack_sc_entries_args.output_directory = output_directory;
      unpack_sc_entries_args.pre_cb = &pkg_pfs_unpack_pre_cb;
      unpack_sc_entries_args.pre_cb_arg = NULL;
    }
    pkg_enum_entries(s_pkg, &pkg_unpack_sc_entries_cb, &unpack_sc_entries_args, s_unpack_extra_sc_entries);
  }

  if (s_dump_sfo) {
    data = pkg_locate_entry_data(s_pkg, PKG_ENTRY_ID__PARAM_SFO, NULL, &data_size);
    if (data) {
      sfo = sfo_alloc();
      if (!sfo) {
        warning("Unable to allocate memory for system file object.");
        goto error;
      }
      if (!sfo_load_from_memory(sfo, data, data_size)) {
        warning("Unable to load system file object.");
        goto error;
      }
      if (s_backport) {
        sfo_backport(sfo, s_sdk_version);
        info("(--backport affects this printed dump only; unpack with --backport to rewrite the extracted param.sfo)");
      }
      sfo_dump(sfo);

      sfo_free(sfo);
      sfo = NULL;
    } else {
      warning("System file object data is not found.");
    }
  }

  if (s_dump_playgo) {
    data = pkg_locate_entry_data(s_pkg, PKG_ENTRY_ID__PLAYGO_CHUNK_DAT, NULL, &data_size);
    if (data) {
      plgo = playgo_alloc();
      if (!plgo) {
        warning("Unable to allocate memory for playgo object.");
        goto error;
      }
      if (!playgo_load_from_memory(plgo, data, data_size)) {
        warning("Unable to load playgo file object.");
        goto error;
      }
      playgo_dump(plgo);

      playgo_free(plgo);
      plgo = NULL;
    } else {
      if (BE32(s_pkg->hdr->content_type) == CONTENT_TYPE_GD)
        warning("Playgo data is not found.");
    }
  }

  ret = 0;

error:
  if (plgo)
    playgo_free(plgo);
  if (sfo)
    sfo_free(sfo);

  return ret;
}

static int pkg_unpack_handler(void* arg) {
  char output_directory[PATH_MAX];
  struct pkg_table_entry* entry;
  struct pkg_unpack_sc_entries_cb_args unpack_sc_entries_args;
  struct pfs* inner_pfs = NULL;
  struct pfs* outer_pfs = NULL;
  uint8_t* data;
  uint32_t data_size;
  struct sfo* sfo = NULL;
  struct playgo* plgo = NULL;
  int shareparam_created;
  int ret = 1;

  assert(s_pkg != NULL);

  UNUSED(arg);

  if (!s_pfs) {
    outer_pfs = s_pkg->pfs;
    inner_pfs = s_pkg->inner_pfs;
  } else {
    inner_pfs = s_pfs;
  }

  if (s_unpack_sc_entries) {
    memset(&unpack_sc_entries_args, 0, sizeof(unpack_sc_entries_args));
    {
      snprintf(output_directory, sizeof(output_directory), "%s/Sc0/", s_output_directory);
      unpack_sc_entries_args.output_directory = output_directory;
      unpack_sc_entries_args.pre_cb = &pkg_pfs_unpack_pre_cb;
      unpack_sc_entries_args.pre_cb_arg = NULL;
    }
    pkg_enum_entries(s_pkg, &pkg_unpack_sc_entries_cb, &unpack_sc_entries_args, s_unpack_extra_sc_entries);

    if (s_gp4_file && BE32(s_pkg->hdr->content_type) == CONTENT_TYPE_GD && !pkg_is_patch(s_pkg)) {
      // Create shareparam.json for game data if not exists.
      entry = pkg_find_entry(s_pkg, PKG_ENTRY_ID__SHAREPARAM_JSON);
      if (!entry) {
        if (pkg_create_dummy_shareparam_json(s_pkg, output_directory, PKG_ENTRY_NAME__SHAREPARAM_JSON, &shareparam_created)) {
          if (shareparam_created)
            warning("Share parameters file is not found, dummy file was created.");
        } else {
          warning("Unable to create share parameters file.");
        }
      }
    }
  }

  if (s_dump_sfo) {
    data = pkg_locate_entry_data(s_pkg, PKG_ENTRY_ID__PARAM_SFO, NULL, &data_size);
    if (data) {
      sfo = sfo_alloc();
      if (!sfo) {
        warning("Unable to allocate memory for system file object.");
        goto error;
      }
      if (!sfo_load_from_memory(sfo, data, data_size)) {
        warning("Unable to load system file object.");
        goto error;
      }
      if (s_backport) {
        sfo_backport(sfo, s_sdk_version);
        info("(--backport affects this printed dump only; unpack with --backport to rewrite the extracted param.sfo)");
      }
      sfo_dump(sfo);

      sfo_free(sfo);
      sfo = NULL;
    } else {
      warning("System file object data is not found.");
    }
  }

  if (s_dump_playgo) {
    data = pkg_locate_entry_data(s_pkg, PKG_ENTRY_ID__PLAYGO_CHUNK_DAT, NULL, &data_size);
    if (data) {
      plgo = playgo_alloc();
      if (!plgo) {
        warning("Unable to allocate memory for playgo object.");
        goto error;
      }
      if (!playgo_load_from_memory(plgo, data, data_size)) {
        warning("Unable to load playgo file object.");
        goto error;
      }
      playgo_dump(plgo);

      playgo_free(plgo);
      plgo = NULL;
    } else {
      if (BE32(s_pkg->hdr->content_type) == CONTENT_TYPE_GD)
        warning("Playgo data is not found.");
    }
  }

  if (s_gp4_file) {
    if (!pkg_generate_gp4_project(s_pkg, s_pfs ? s_pfs : s_pkg->inner_pfs, s_meta_data_in_file, s_gp4_file, s_output_directory, s_meta_data_out_file, s_use_random_passcode, s_all_compressed))
      warning("Unable to generate GP4 project file for PKG file: %s", s_input_file_path);
  }

  if (s_unpack_outer_pfs && outer_pfs) {
    // XXX: reuse path variable
    snprintf(output_directory, sizeof(output_directory), "%s/outer_pfs_image.dat", s_output_directory);

    if (!pfs_dump_to_file(outer_pfs, output_directory, &pkg_pfs_unpack_pre_cb, NULL))
      warning("Unable to unpack file '%s' from PKG file: %s", "outer_pfs_image.dat", s_input_file_path);
  }

  if (s_unpack_inner_pfs && outer_pfs) {
    snprintf(output_directory, sizeof(output_directory), "%s/", s_output_directory);

    if (!pfs_unpack_single(outer_pfs, PKG_PFS_IMAGE_FILE_NAME, output_directory, &pkg_pfs_unpack_pre_cb, NULL))
      warning("Unable to unpack file '%s' from PKG file: %s", PKG_PFS_IMAGE_FILE_NAME, s_input_file_path);
  }

  if (!s_no_unpack) {
    snprintf(output_directory, sizeof(output_directory), "%s/Image0", s_output_directory);

    if (!pfs_unpack_all(inner_pfs, output_directory, &pkg_pfs_unpack_pre_cb, NULL)) {
      if (!s_pfs)
        error("Unable to unpack PKG file: %s", s_input_file_path);
      else
        error("Unable to unpack PFS file: %s", s_pfs_image_data_file);
    }
  }

  ret = 0;

error:
  if (plgo)
    playgo_free(plgo);
  if (sfo)
    sfo_free(sfo);

  return ret;
}

#if defined(ENABLE_REPACK_SUPPORT)
  static int pkg_repack_self(struct pkg* pkg, const char* file_path, const char* real_file_path) {
    struct pfs_file_context* file = NULL;
    struct self* self = NULL;
    struct self* new_self = NULL;
    struct file_map* elf_map = NULL;
    struct elf* elf = NULL;
    uint8_t* data = NULL;
    uint8_t* new_self_data = NULL;
    pfs_ino ino;
    int status = 0;

    assert(pkg != NULL);
    assert(pkg->inner_pfs != NULL);
    assert(file_path != NULL);
    assert(real_file_path != NULL);

    if (!pfs_lookup_path_user(pkg->inner_pfs, file_path, &ino)) {
      warning("Unable to lookup SELF file: %s\n", file_path);
      goto error;
    }

    file = pfs_get_file(pkg->inner_pfs, ino);
    if (!file) {
      warning("Unable to get SELF file: %s\n", file_path);
      goto error;
    }

    elf_map = map_file(real_file_path);
    if (!elf_map)
      goto error;

    elf = elf_alloc(elf_map->data, elf_map->size, 0);
    if (!elf)
      goto error;

    data = (uint8_t*)malloc(file->file_size);
    if (!data)
      goto error;
    memset(data, 0, file->file_size);

    if (!pfs_file_read(file, 0, data, file->file_size))
      goto error;

    self = self_alloc(data, (size_t)file->file_size);
    if (!self)
      goto error;

    new_self_data = (uint8_t*)malloc(file->file_size);
    if (!new_self_data)
      goto error;
    memcpy(new_self_data, data, file->file_size);

    new_self = self_alloc(new_self_data, (size_t)file->file_size);
    if (!new_self)
      goto error;

    status = self_make_fake_signed(new_self, elf);
    if (!status) {
      warning("Unable to make fake signed elf.");
      goto error;
    }

    if (!write_to_file("test.fself", new_self_data, file->file_size, NULL, 0644))
      warning("Unable to write file.");

error:
    if (new_self)
      self_free(new_self);

    if (new_self_data)
      free(new_self_data);

    if (self)
      self_free(self);

    if (data)
      free(data);

    if (elf)
      elf_free(elf);

    if (elf_map)
      unmap_file(elf_map);

    if (file)
      pfs_free_file(file);

    return status;
  }

  static int pkg_repack_self_cb(void* arg, const char* parent_name, const char* child_name, unsigned int mode) {
    struct pkg_repack_self_cb_args* args = (struct pkg_repack_self_cb_args*)arg;
    char file_path[PATH_MAX];
    char file_path_fixed[PATH_MAX];
    uint32_t elf_magic = ELF_MAGIC;
    size_t i;
    int found;
    char* p;

    static const char* extensions[] = {
      ".bin",
      ".self",
      ".sprx",
      ".elf",
      ".prx",
    };
    static const size_t extension_count = COUNT_OF(extensions);

    assert(args != NULL);
    assert(args->pkg != NULL);
    assert(args->elf_directory != NULL);
    assert(parent_name != NULL);
    assert(child_name != NULL);

    snprintf(file_path, sizeof(file_path), "%s/%s", parent_name, child_name);

    p = strstr(file_path, args->elf_directory);
    if (p)
      strncpy(file_path_fixed, p + strlen(args->elf_directory), sizeof(file_path_fixed));
    else
      strncpy(file_path_fixed, args->elf_directory, sizeof(file_path_fixed));

    if (ends_with_nocase(file_path_fixed, RIGHT_SPRX_PATH)) {
      info("Skipping SELF file: %s", file_path_fixed);
      goto done;
    }

    if (S_ISREG(mode)) {
      found = 0;
      for (i = 0; i < extension_count; ++i) {
        if (ends_with_nocase(child_name, extensions[i])) {
          found = 1;
          break;
        }
      }
      if (!found)
        goto done;

      if (!is_file(file_path) && !is_readable(file_path))
        goto done;
      if (!file_has_magic(file_path, &elf_magic, sizeof(elf_magic)))
        goto done;

      info("Repacking SELF file: %s", file_path_fixed);
      pkg_repack_self(args->pkg, file_path_fixed, file_path);
    }

done:
    return CB_RESULT_CONTINUE;
  }

  static int pkg_repack_handler(void* arg) {
    uint64_t file_size;
    struct file_map* map = NULL;
    struct file_map* submap = NULL;
    struct pkg_header hdr;
    uint8_t* entry_data;
    uint32_t entry_size;
    uint64_t playgo_chunk_count, playgo_chunk_idx;
    uint8_t playgo_chunk_hash[PKG_HASH_SIZE];
    struct pkg_repack_self_cb_args repack_self_args;
    int ret = 1;

    assert(s_pkg != NULL);
    assert(arg != NULL);

    file_size = *(uint64_t*)arg;

    memcpy(&hdr, s_pkg->hdr, sizeof(*s_pkg->hdr));

    map = map_file_for_write(s_output_file_path, file_size, 0644);
    if (!map)
      goto error;

    memcpy(map->data, s_pkg->map->data, s_pkg->pfs_image_offset);

    submap = map_file_sub_region(map, s_pkg->pfs_image_offset, s_pkg->pfs_image_size);
    if (!submap)
      goto error;

    ret = pfs_repack_internal(s_pkg->pfs, submap);

    if (!s_no_elf_repack) {
      memset(&repack_self_args, 0, sizeof(repack_self_args));

      repack_self_args.pkg = s_pkg;
      repack_self_args.elf_directory = s_plaintext_elf_directory;

      list_directory_r(s_plaintext_elf_directory, &pkg_repack_self_cb, &repack_self_args);
    }

    if (!s_no_hash_recalc) {
      entry_data = pkg_locate_entry_data(s_pkg, PKG_ENTRY_ID__PLAYGO_CHUNK_SHA, NULL, &entry_size);
      if (entry_data) {
        entry_data = map->data + (entry_data - s_pkg->map->data) + PKG_PLAYGO_CHUNK_HASH_TABLE_OFFSET;
        playgo_chunk_count = s_pkg->pfs_image_size / PKG_PLAYGO_PFS_CHUNK_SIZE;
        for (playgo_chunk_idx = 0; playgo_chunk_idx < playgo_chunk_count; ++playgo_chunk_idx) {
          sha256_buffer(submap->data + playgo_chunk_idx * PKG_PLAYGO_PFS_CHUNK_SIZE, PKG_PLAYGO_PFS_CHUNK_SIZE, playgo_chunk_hash);
          memcpy(entry_data, playgo_chunk_hash, PKG_PLAYGO_CHUNK_HASH_SIZE);
          entry_data += PKG_PLAYGO_CHUNK_HASH_SIZE;
        }
      }

      sha256_buffer(submap->data, s_pkg->pfs_signed_size, hdr.pfs_signed_digest);
      sha256_buffer(submap->data, s_pkg->pfs_image_size, hdr.pfs_image_digest);
    }

    memcpy(map->data, &hdr, sizeof(hdr));

error:
    if (submap)
      unmap_file(submap);

    if (map)
      unmap_file(map);

    return ret;
  }
#endif

/* Parse a make_fself --ptype value: a keyword or a raw number. Returns 1 on ok. */
static int parse_mkfs_ptype(const char* s, uint64_t* out) {
  static const struct { const char* name; uint64_t val; } map[] = {
    { "fake",          SELF_PTYPE_FAKE },
    { "npdrm_exec",    SELF_PTYPE_NPDRM_EXEC },
    { "npdrm_dynlib",  SELF_PTYPE_NPDRM_DYNLIB },
    { "system_exec",   SELF_PTYPE_SYSTEM_EXEC },
    { "system_dynlib", SELF_PTYPE_SYSTEM_DYNLIB },
    { "host_kernel",   SELF_PTYPE_BIOS_KERNEL },
    { "secure_module", SELF_PTYPE_SECURE_MODULE },
    { "secure_kernel", SELF_PTYPE_SECURE_LOADER },
  };
  char* end = NULL;
  size_t i;
  for (i = 0; i < sizeof(map) / sizeof(map[0]); ++i) {
    if (strcasecmp(s, map[i].name) == 0) {
      *out = map[i].val;
      return 1;
    }
  }
  *out = (uint64_t)strtoull(s, &end, 0);
  return (end && *end == '\0' && end != s) ? 1 : 0;
}

static int parse_args(int argc, char* argv[]) {
  int option_index;
  size_t size;
  const char* part;
  const char* separator;
  size_t part_length;
  char* tmp_path;
  char* p;
  int c;
  int status = 1;

  static const char* short_options = "hi:l:u:r:D:G:U:F:";
  static struct option long_options[] = {
    { "help", ARG_NONE, ARG_NULL, 'h' },

    { "info", ARG_REQ, ARG_NULL, 'i' },
    { "list", ARG_REQ, ARG_NULL, 'l' },
    { "unpack", ARG_REQ, ARG_NULL, 'u' },
#if defined(ENABLE_REPACK_SUPPORT)
    { "repack", ARG_REQ, ARG_NULL, 'r' },
#endif
    { "decrypt-self", ARG_REQ, ARG_NULL, 'D' },
    { "downgrade-elf", ARG_REQ, ARG_NULL, 'G' },
    { "unfself", ARG_REQ, ARG_NULL, 'U' },
    { "make-fself", ARG_REQ, ARG_NULL, 'F' },

    { "paid", ARG_REQ, &s_opt_mkfs_paid_flag, 1 },
    { "ptype", ARG_REQ, &s_opt_mkfs_ptype_flag, 1 },
    { "app-version", ARG_REQ, &s_opt_mkfs_app_version_flag, 1 },
    { "fw-version", ARG_REQ, &s_opt_mkfs_fw_version_flag, 1 },
    { "auth-info", ARG_REQ, &s_opt_mkfs_auth_info_flag, 1 },

    { "key-content-id", ARG_REQ, &s_opt_key_content_id_flag, 1 },
#if defined(ENABLE_REPACK_SUPPORT)
    { "content-id", ARG_NONE, &s_opt_content_id_flag, 1 },
#endif
    { "passcode", ARG_REQ, &s_opt_passcode_flag, 1 },
#ifdef ENABLE_SD_KEYGEN
    { "sealed-key-file", ARG_REQ, &s_opt_sealed_key_file_flag, 1 },
#endif
    { "encdec-tweak-key", ARG_REQ, &s_opt_encdec_tweak_key_flag, 1 },
    { "encdec-data-key", ARG_REQ, &s_opt_encdec_data_key_flag, 1 },
    { "sign-key", ARG_REQ, &s_opt_sign_key_flag, 1 },
    { "sc0-key", ARG_REQ, &s_opt_sc0_key_flag, 1 },
    { "use-meta-data-file", ARG_REQ, &s_opt_use_meta_data_flag, 1 },
    { "dump-meta-data-file", ARG_REQ, &s_opt_dump_meta_data_flag, 1 },
    { "pfs-image-data-file", ARG_REQ, &s_opt_pfs_image_data_file_flag, 1 },
    { "generate-gp4", ARG_REQ, &s_opt_gp4_file_flag, 1 },
    { "unpack-outer-pfs", ARG_NONE, &s_opt_unpack_outer_pfs_flag, 1 },
    { "unpack-inner-pfs", ARG_NONE, &s_opt_unpack_inner_pfs_flag, 1 },
    { "unpack-sc-entries", ARG_NONE, &s_opt_unpack_sc_entries_flag, 1 },
    { "unpack-extra-sc-entries", ARG_NONE, &s_opt_unpack_extra_sc_entries_flag, 1 },
    { "use-splitted-files", ARG_NONE, &s_opt_use_splitted_files_flag, 1 },
    { "no-unpack", ARG_NONE, &s_opt_no_unpack_flag, 1 },
    { "no-signature-check", ARG_NONE, &s_opt_no_signature_check_flag, 1 },
    { "no-icv-check", ARG_NONE, &s_opt_no_icv_check_flag, 1 },
#if defined(ENABLE_REPACK_SUPPORT)
    { "no-hash-recalc", ARG_NONE, &s_opt_no_hash_recalc_flag, 1 },
    { "no-elf-repack", ARG_NONE, &s_opt_no_elf_repack_flag, 1 },
#endif
    { "decrypt-elfs", ARG_NONE, &s_opt_decrypt_elfs_flag, 1 },
    { "downgrade", ARG_NONE, &s_opt_downgrade_flag, 1 },
    { "rewrap-fself", ARG_NONE, &s_opt_rewrap_fself_flag, 1 },
    { "dump-sfo", ARG_NONE, &s_opt_dump_sfo_flag, 1 },
    { "backport", ARG_NONE, &s_opt_backport_flag, 1 },
    { "sdk-version", ARG_REQ, &s_opt_sdk_version_flag, 1 },
    { "dump-playgo", ARG_NONE, &s_opt_dump_playgo_flag, 1 },
    { "dump-final-keys", ARG_NONE, &s_opt_dump_final_keys_flag, 1 },
#if defined(ENABLE_SD_KEYGEN)
    { "dump-sd-info", ARG_NONE, &s_opt_dump_sd_info_flag, 1 },
#endif
    { "use-random-passcode", ARG_NONE, &s_opt_use_random_passcode_flag, 1 },
    { "all-compressed", ARG_NONE, &s_opt_all_compressed_flag, 1 },

    { 0, 0, 0, 0 },
  };

  while ((c = option_index = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1) {
    switch (c) {
      case '?':
        status = 0;
        goto done;

      case 'h':
        show_version();
        show_usage(argv);
        goto done;

      case 'i':
        s_cmd_info = 1;
        if (s_input_file_path)
          free(s_input_file_path);
        s_input_file_path = strdup(optarg);
        goto get_args;

      case 'l':
        s_cmd_list = 1;
        if (s_input_file_path)
          free(s_input_file_path);
        s_input_file_path = strdup(optarg);
        goto done;

      case 'u':
        s_cmd_unpack = 1;
        if (s_input_file_path)
          free(s_input_file_path);
        s_input_file_path = strdup(optarg);
        goto get_args;

#if defined(ENABLE_REPACK_SUPPORT)
      case 'r':
        s_cmd_repack = 1;
        if (s_input_file_path)
          free(s_input_file_path);
        s_input_file_path = strdup(optarg);
        goto get_args;
#endif

      case 'D':
        s_cmd_decrypt_self = 1;
        if (s_input_file_path)
          free(s_input_file_path);
        s_input_file_path = strdup(optarg);
        goto get_args;

      case 'G':
        s_cmd_downgrade_elf = 1;
        if (s_input_file_path)
          free(s_input_file_path);
        s_input_file_path = strdup(optarg);
        goto get_args;

      case 'U':
        s_cmd_unfself = 1;
        if (s_input_file_path)
          free(s_input_file_path);
        s_input_file_path = strdup(optarg);
        goto get_args;

      case 'F':
        s_cmd_make_fself = 1;
        if (s_input_file_path)
          free(s_input_file_path);
        s_input_file_path = strdup(optarg);
        goto get_args;

      case 0:
        if (s_opt_key_content_id_flag) {
          s_key_content_id = strdup(optarg); s_opt_key_content_id_flag = 0;
#if 0
          if (!s_key_content_id) || strlen(s_key_content_id) != KEYMGR_CONTENT_ID_SIZE)
            error("Invalid key content ID specified.");
#else
          if (!s_key_content_id)
          error("Invalid key content ID specified.");
#endif
        }
#if defined(ENABLE_REPACK_SUPPORT)
        if (s_opt_content_id_flag) {
          s_content_id = strdup(optarg); s_opt_content_id_flag = 0;
          if (!s_content_id || strlen(s_content_id) != KEYMGR_CONTENT_ID_SIZE)
            error("Invalid content ID specified.");
        }
#endif
        if (s_opt_passcode_flag) {
          s_passcode = strdup(optarg); s_opt_passcode_flag = 0;
          if (!s_passcode || strlen(s_passcode) != KEYMGR_PASSCODE_SIZE)
            error("Invalid passcode specified.");
        }
#ifdef ENABLE_SD_KEYGEN
        if (s_opt_sealed_key_file_flag) {
          s_sealed_key_file = strdup(optarg); s_opt_sealed_key_file_flag = 0;
          if (!s_sealed_key_file || !is_file(s_sealed_key_file))
            error("Invalid sealed key file specified.");
        }
#endif
        if (s_opt_encdec_tweak_key_flag) {
          s_encdec_tweak_key = x_to_u8_buffer(optarg, &size); s_opt_encdec_tweak_key_flag = 0;
          if (!s_encdec_tweak_key || size != KEYMGR_AES_KEY_SIZE)
            error("Invalid enc/dec tweak key specified.");
        }
        if (s_opt_encdec_data_key_flag) {
          s_encdec_data_key = x_to_u8_buffer(optarg, &size); s_opt_encdec_data_key_flag = 0;
          if (!s_encdec_data_key || size != KEYMGR_AES_KEY_SIZE)
            error("Invalid enc/dec data key specified.");
        }
        if (s_opt_sign_key_flag) {
          s_sign_key = x_to_u8_buffer(optarg, &size); s_opt_sign_key_flag = 0;
          if (!s_sign_key || size != KEYMGR_HMAC_KEY_SIZE)
            error("Invalid signing key specified.");
        }
        if (s_opt_sc0_key_flag) {
          s_sc0_key = x_to_u8_buffer(optarg, &size); s_opt_sc0_key_flag = 0;
          if (!s_sc0_key || size != KEYMGR_SC0_KEY_SIZE)
            error("Invalid sc0 key specified.");
        }
        if (s_opt_use_meta_data_flag) {
          s_meta_data_in_file = strdup(optarg); s_opt_use_meta_data_flag = 0;
          if (!s_meta_data_in_file || ((is_exists(s_meta_data_in_file) && !is_readable(s_meta_data_in_file)) || is_directory(s_meta_data_in_file)))
            error("Invalid input meta data file specified.");
        }
        if (s_opt_dump_meta_data_flag) {
          s_meta_data_out_file = strdup(optarg); s_opt_dump_meta_data_flag = 0;
          if (!s_meta_data_out_file || ((is_exists(s_meta_data_out_file) && !is_writeable(s_meta_data_out_file)) || is_directory(s_meta_data_out_file)))
            error("Invalid output meta data file specified.");
        }
        if (s_opt_pfs_image_data_file_flag) {
          s_pfs_image_data_file = strdup(optarg); s_opt_pfs_image_data_file_flag = 0;
          if (!s_pfs_image_data_file || ((is_exists(s_pfs_image_data_file) && !is_readable(s_pfs_image_data_file)) || is_directory(s_pfs_image_data_file)))
            error("Invalid PFS image data file specified.");
        }
        if (s_opt_gp4_file_flag) {
          s_gp4_file = strdup(optarg); s_opt_gp4_file_flag = 0;
          if (!s_gp4_file || ((is_exists(s_gp4_file) && !is_writeable(s_gp4_file)) || is_directory(s_gp4_file)))
            error("Invalid GP4 file specified.");
        }
        if (s_opt_no_unpack_flag) {
          s_no_unpack = 1;
          s_opt_no_unpack_flag = 0;
        }
        if (s_opt_unpack_outer_pfs_flag) {
          s_unpack_outer_pfs = 1;
          s_opt_unpack_outer_pfs_flag = 0;
        }
        if (s_opt_unpack_inner_pfs_flag) {
          s_unpack_inner_pfs = 1;
          s_opt_unpack_inner_pfs_flag = 0;
        }
        if (s_opt_unpack_sc_entries_flag) {
          s_unpack_sc_entries = 1;
          s_opt_unpack_sc_entries_flag = 0;
        }
        if (s_opt_unpack_extra_sc_entries_flag) {
          s_unpack_extra_sc_entries = 1;
          s_opt_unpack_extra_sc_entries_flag = 0;
        }
        if (s_opt_use_splitted_files_flag) {
          s_use_splitted_files = 1;
          s_opt_use_splitted_files_flag = 0;
        }
        if (s_opt_no_signature_check_flag) {
          s_no_signature_check = 1;
          s_opt_no_signature_check_flag = 0;
        }
        if (s_opt_no_icv_check_flag) {
          s_no_icv_check = 1;
          s_opt_no_icv_check_flag = 0;
        }
#if defined(ENABLE_REPACK_SUPPORT)
        if (s_opt_no_hash_recalc_flag) {
          s_no_hash_recalc = 1;
          s_opt_no_hash_recalc_flag = 0;
        }
        if (s_opt_no_elf_repack_flag) {
          s_no_elf_repack = 1;
          s_opt_no_elf_repack_flag = 0;
        }
#endif
        if (s_opt_decrypt_elfs_flag) {
          s_decrypt_elfs = 1;
          s_opt_decrypt_elfs_flag = 0;
        }
        if (s_opt_downgrade_flag) {
          s_downgrade = 1;
          s_opt_downgrade_flag = 0;
        }
        if (s_opt_rewrap_fself_flag) {
          s_rewrap_fself = 1;
          s_opt_rewrap_fself_flag = 0;
        }
        if (s_opt_mkfs_paid_flag) {
          s_mkfs_paid = (uint64_t)strtoull(optarg, NULL, 0);
          s_mkfs_paid_set = 1; s_opt_mkfs_paid_flag = 0;
        }
        if (s_opt_mkfs_ptype_flag) {
          if (!parse_mkfs_ptype(optarg, &s_mkfs_ptype))
            error("Invalid program type: %s", optarg);
          s_mkfs_ptype_set = 1; s_opt_mkfs_ptype_flag = 0;
        }
        if (s_opt_mkfs_app_version_flag) {
          s_mkfs_app_version = (uint64_t)strtoull(optarg, NULL, 0);
          s_mkfs_app_version_set = 1; s_opt_mkfs_app_version_flag = 0;
        }
        if (s_opt_mkfs_fw_version_flag) {
          s_mkfs_fw_version = (uint64_t)strtoull(optarg, NULL, 0);
          s_mkfs_fw_version_set = 1; s_opt_mkfs_fw_version_flag = 0;
        }
        if (s_opt_mkfs_auth_info_flag) {
          size_t ai_size = 0;
          s_mkfs_auth_info = x_to_u8_buffer(optarg, &ai_size);
          s_opt_mkfs_auth_info_flag = 0;
          if (!s_mkfs_auth_info || ai_size != 0x88)
            error("Invalid auth info (need 0x88 bytes of hex).");
        }
        if (s_opt_dump_sfo_flag) {
          s_dump_sfo = 1;
          s_opt_dump_sfo_flag = 0;
        }
        if (s_opt_backport_flag) {
          s_backport = 1;
          s_opt_backport_flag = 0;
        }
        if (s_opt_sdk_version_flag) {
          s_sdk_version = strdup(optarg);
          s_opt_sdk_version_flag = 0;
          if (!s_sdk_version || strlen(s_sdk_version) != 8)
            error("Invalid SDK version specified (expected 8 hex digits, e.g. 05050000).");
        }
        if (s_opt_dump_playgo_flag) {
          s_dump_playgo = 1;
          s_opt_dump_playgo_flag = 0;
        }
        if (s_opt_dump_final_keys_flag) {
          s_dump_final_keys = 1;
          s_opt_dump_final_keys_flag = 0;
        }
#if defined(ENABLE_SD_KEYGEN)
        if (s_opt_dump_sd_info_flag) {
          s_dump_sd_info = 1;
          s_opt_dump_sd_info_flag = 0;
        }
#endif
        if (s_opt_use_random_passcode_flag) {
          s_use_random_passcode = 1;
          s_opt_use_random_passcode_flag = 0;
        }
        if (s_opt_all_compressed_flag) {
          s_all_compressed = 1;
          s_opt_all_compressed_flag = 0;
        }
        break;

      default:
        abort();
    }
  }

get_args:;
  if (s_cmd_decrypt_self) {
    if (argc - optind < 1)
      error("Decrypt-self command needs output ELF file path!\n");
    s_output_file_path = strdup(argv[optind++]);
    goto done;
  }

  if (s_cmd_downgrade_elf) {
    if (argc - optind < 1)
      error("Downgrade-elf command needs output ELF file path!\n");
    s_output_file_path = strdup(argv[optind++]);
    goto done;
  }

  if (s_cmd_unfself) {
    if (argc - optind < 1)
      error("Unfself command needs output ELF file path!\n");
    s_output_file_path = strdup(argv[optind++]);
    goto done;
  }

  if (s_cmd_make_fself) {
    if (argc - optind < 1)
      error("Make-fself command needs output SELF file path!\n");
    s_output_file_path = strdup(argv[optind++]);
    goto done;
  }

  if (s_cmd_info) {
    if (s_unpack_sc_entries) {
      if (argc - optind < 1) {
        error("Info command needs output directory if you want to unpack SC entries!\n");
      } else {
        strncpy(s_output_directory, argv[optind++], sizeof(s_output_directory));
      }
    }
    goto done;
  }

  if (s_cmd_unpack) {
    if (argc - optind < 1) {
      error("Unpack command needs output directory!\n");
    } else {
      strncpy(s_output_directory, argv[optind++], sizeof(s_output_directory));
      if (optind < argc) {
        utarray_new(s_file_paths, &ut_str_icd);
        while (optind < argc) {
          p = argv[optind++];
          /* Options placed after the command aren't parsed as options (the
             command handler jumps straight here); don't mistake them for
             selective-unpack file filters. Skip and warn to place them first. */
          if (p[0] == '-') {
            warning("Ignoring '%s': options must be placed before the command (e.g. '%s ... -u <in> <out>').", p, p);
            continue;
          }
          size = strlen(p);
          if (size > 0) {
            part = p;
            while (*part != '\0') {
              separator = path_get_separator(part);
              if (*separator != '\0')
                part_length = separator - p;
              else
                part_length = size;
              if (part_length > 0) {
                tmp_path = (char*)malloc(part_length + 1);
                if (!tmp_path)
                  error("No memory.");
                strncpy(tmp_path, p, part_length);
                tmp_path[part_length] = '\0';
                utarray_push_back(s_file_paths, &tmp_path);
              }
              part = path_skip_separator(separator);
            }
          }
        }
        /* If every trailing arg was a skipped option, there is no file filter —
           fall back to unpacking everything (NULL == no selective list). */
        if (utarray_len(s_file_paths) == 0) {
          utarray_free(s_file_paths);
          s_file_paths = NULL;
        }
      }
    }

    if ((s_meta_data_in_file || s_meta_data_out_file) && !s_gp4_file)
      error("Meta data file options are working in conjunction with GP4 project generation!");

    if (s_meta_data_in_file && !s_pfs_image_data_file)
      error("Input meta data file option needs to be used with pfs image data file option!");

    goto done;
  }

#if defined(ENABLE_REPACK_SUPPORT)
  if (s_cmd_repack) {
    if (s_no_elf_repack) {
      if (argc - optind < 1)
        error("Repack command needs output file path!\n");
      else
        s_output_file_path = strdup(argv[optind++]);
    } else {
      if (argc - optind < 1)
        error("Repack command needs output file path!\n");
      else if (argc - optind < 2)
        error("Repack command needs plaintext elf directory!\n");
      else {
        s_output_file_path = strdup(argv[optind++]);
        s_plaintext_elf_directory = strdup(argv[optind++]);
      }
    }

    goto done;
  }
#endif

done:
  return status;
}

int main(int argc, char* argv[]) {
  char program_directory[PATH_MAX];
  char config_file_path[PATH_MAX];
  int is_package_input_file, any_cmd;
  char* p;
  int ret = 0;

  if (argc < 2) {
    show_version();
    show_usage(argv);
    exit(1);
  }

  atexit(&cleanup);

  char *program_path = argv[0];
  #ifdef _WIN32
  _get_pgmptr(&program_path);
  #endif
  path_get_directory(program_directory, sizeof(program_directory), program_path);
  snprintf(config_file_path, sizeof(config_file_path), "%s%s%s", program_directory, (*program_directory != '\0') ? "/" : "", CONFIG_FILE);

  if (!crypto_initialize())
    error("Unable to initialize crypto.");

  if (!keymgr_initialize(config_file_path))
    error("Unable to initialize key manager.");

	if (!parse_args(argc, argv)) {
		show_version();
		show_usage(argv);
		exit(1);
	}

  if (s_cmd_decrypt_self) {
    if (!is_file(s_input_file_path) || !is_readable(s_input_file_path))
      error("Invalid input SELF file specified: %s", s_input_file_path);
    ret = self_decrypt_file(s_input_file_path, s_output_file_path) ? 0 : 1;
    if (ret == 0)
      info("Decrypted SELF to: %s", s_output_file_path);
    return ret;
  }

  if (s_cmd_downgrade_elf) {
    uint32_t target = s_sdk_version ? (uint32_t)strtoul(s_sdk_version, NULL, 16) : 0;
    if (!is_file(s_input_file_path) || !is_readable(s_input_file_path))
      error("Invalid input ELF file specified: %s", s_input_file_path);
    if (!copy_file_bytes(s_input_file_path, s_output_file_path))
      error("Unable to copy '%s' to '%s'.", s_input_file_path, s_output_file_path);
    ret = (elf_downgrade_file(s_output_file_path, target) >= 0) ? 0 : 1;
    if (ret == 0)
      info("Downgraded ELF to: %s (target sdk 0x%08" PRIX32 ")", s_output_file_path, target);
    return ret;
  }

  if (s_cmd_unfself) {
    if (!is_file(s_input_file_path) || !is_readable(s_input_file_path))
      error("Invalid input self file specified: %s", s_input_file_path);
    ret = (self_unfself_file(s_input_file_path, s_output_file_path) == 1) ? 0 : 1;
    if (ret == 0)
      info("Unfself'd to: %s", s_output_file_path);
    return ret;
  }

  if (s_cmd_make_fself) {
    struct makefself_opts opts;
    if (!is_file(s_input_file_path) || !is_readable(s_input_file_path))
      error("Invalid input ELF file specified: %s", s_input_file_path);
    makefself_opts_default(&opts);
    if (s_mkfs_paid_set)        opts.paid = s_mkfs_paid;
    if (s_mkfs_ptype_set)       opts.ptype = s_mkfs_ptype;
    if (s_mkfs_app_version_set) opts.app_version = s_mkfs_app_version;
    if (s_mkfs_fw_version_set)  opts.fw_version = s_mkfs_fw_version;
    opts.auth_info = s_mkfs_auth_info;
    ret = (self_make_fself_file(s_input_file_path, s_output_file_path, &opts) == 1) ? 0 : 1;
    if (ret == 0)
      info("Made fake-signed SELF: %s", s_output_file_path);
    return ret;
  }

  any_cmd = 0;
  any_cmd |= s_cmd_info;
  any_cmd |= s_cmd_list;
  any_cmd |= s_cmd_unpack;
#if defined(ENABLE_REPACK_SUPPORT)
  any_cmd |= s_cmd_repack;
#endif

  if (any_cmd) {
    if (s_use_splitted_files) {
      p = strrchr(s_input_file_path, '%');
      if (!p)
        error("Using splitted files but input file pattern doesn't contain %% symbol: %s", s_input_file_path);
    }

    if (!is_file(s_input_file_path) || !is_readable(s_input_file_path)) {
      if (s_use_splitted_files) {
        if (p) {
          is_package_input_file = 1;
          goto input_file_ok;
        }
      }
error_invalid_input_file:
      error("Invalid input file specified: %s", s_input_file_path);
    }

    is_package_input_file = file_has_magic(s_input_file_path, s_pkg_magic, sizeof(s_pkg_magic));

input_file_ok:
    if (s_cmd_unpack || (s_cmd_info && s_unpack_sc_entries)) {
      rtrim_slashes(s_output_directory);
      if (is_exists(s_output_directory)) {
        if (!is_directory(s_output_directory) || !is_writeable(s_output_directory))
          error("Invalid output directory specified: %s", s_output_directory);
      } else {
        if (!make_directories(s_output_directory, 0755))
          error("Unable to create output directory: %s", s_output_directory);
      }
    }

#if defined(ENABLE_REPACK_SUPPORT)
    if (s_cmd_repack) {
      if (!s_no_elf_repack) {
        if (is_package_input_file) {
          if (!is_directory(s_plaintext_elf_directory))
            error("Invalid plaintext elf directory specified: %s", s_plaintext_elf_directory);
        }
      }
      if ((is_exists(s_output_file_path) && !is_writeable(s_output_file_path)) || is_directory(s_output_file_path))
        error("Invalid output file specified: %s", s_output_file_path);
    }
#endif

    if (is_package_input_file) {
      if (s_cmd_info)
        ret = process_pkg(&pkg_info_handler) != 0;
      else if (s_cmd_list)
        ret = process_pkg(&pkg_list_handler) != 0;
      else if (s_cmd_unpack)
        ret = process_pkg(&pkg_unpack_handler) != 0;
#if defined(ENABLE_REPACK_SUPPORT)
      else if (s_cmd_repack)
        ret = process_pkg(&pkg_repack_handler) == 0;
#endif
    } else {
      if (s_cmd_info)
        ret = process_pfs(&pfs_info_handler) != 0;
      else if (s_cmd_list)
        ret = process_pfs(&pfs_list_handler) != 0;
      else if (s_cmd_unpack)
        ret = process_pfs(&pfs_unpack_handler) != 0;
#if defined(ENABLE_REPACK_SUPPORT)
      else if (s_cmd_repack)
        ret = process_pfs(&pfs_repack_handler) != 0;
#endif
    }

    /* Live decrypt/backport over the freshly unpacked tree. */
    if (s_cmd_unpack && ret == 0)
      run_unpack_postproc(s_output_directory);
  } else {
    exit(0);
  }

  return ret;
}

static void show_version(void) {
  printf("PS4 PKG/PFS Tool " PKG_PFS_TOOL_VERSION " (c) 2017-2021 by flatz\n");
  printf("--------------------------------------------\n");
}

static void show_usage(char* argv[]) {
  char exe_name[PATH_MAX];
  path_get_file_name(exe_name, sizeof(exe_name), argv[0]);

  printf("USAGE: %s [options] command\n", exe_name);
  printf("\n");
  printf("COMMANDS                 PARAMETERS                    DESCRIPTION\n");
  printf("------------------------------------------------------------------------------\n");
  printf("  -h, --help                                            Print this help\n");
  printf("  -i, --info <img file>                                 Show information about image\n");
  printf("  -l, --list <img file>                                 List of entries\n");
  printf("  -u, --unpack <img file> <out dir> [file1 file2...]    Unpack files from image\n");
#if defined(ENABLE_REPACK_SUPPORT)
  printf("  -r, --repack <src img file> <dst img file> [elfs dir] Repack image file (with plaintext elfs)\n");
#endif
  printf("  -D, --decrypt-self <in self> <out elf>                Decrypt a real (encrypted) SELF/SPRX to plaintext ELF\n");
  printf("  -U, --unfself <in self> <out elf>                     Extract plaintext ELF from a FAKE-signed SELF (no keys)\n");
  printf("  -G, --downgrade-elf <in elf> <out elf>                Downgrade a plaintext ELF's SDK version (see --sdk-version)\n");
  printf("  -F, --make-fself <in elf> <out self>                  Wrap a plaintext ELF into a fake-signed SELF\n");
  printf("\n");

  printf("OPTIONS                  PARAMETERS                     DESCRIPTION\n");
  printf("------------------------------------------------------------------------------\n");
  printf("  --key-content-id <content id>                         Use keyset of specific content ID\n");
#if defined(ENABLE_REPACK_SUPPORT)
  printf("  --content-id <content id>                             Replace content ID on repacking\n");
#endif
  printf("  --passcode <passcode>                                 Use specific passcode\n");
#ifdef ENABLE_SD_KEYGEN
  printf("  --sealed-key-file <sealed key file>                   Use sealed key file for keys generation\n");
#endif
  printf("  --encdec-tweak-key <key>                              Use specific AES XTS tweak key for enc/dec\n");
  printf("  --encdec-data-key <key>                               Use specific AES XTS data key for enc/dec\n");
  printf("  --sign-key <key>                                      Use specific HMAC SHA256 key for signing\n");
  printf("  --sc0-key <key>                                       Use specific Sc0 key for enc/dec\n");
  printf("  --use-meta-data-file <meta data file>                 Load GP4 meta data from file\n");
  printf("  --dump-meta-data-file <meta data file>                Save GP4 meta data to file\n");
  printf("  --pfs-image-data-file <pfs_image.dat file>            Use plain pfs_image.dat as PFS content of PKG file\n");
  printf("  --generate-gp4 <gp4 file>                             Generate GP4 project from PKG file\n");
  printf("  --unpack-inner-pfs                                    Unpack inner PFS file from PKG file\n");
  printf("  --unpack-outer-pfs                                    Unpack outer PFS file from PKG file\n");
  printf("  --unpack-sc-entries                                   Unpack SC entries from PKG file\n");
  printf("  --unpack-extra-sc-entries                             Unpack extra SC entries from PKG file\n");
  printf("  --use-splitted-files                                  Use splitted PKG chunks\n");
  printf("  --no-unpack                                           Don't unpack main PFS files from PKG file\n");
  printf("  --no-signature-check                                  Skip signature checking\n");
  printf("  --no-icv-check                                        Skip ICV hash checking\n");
#if defined(ENABLE_REPACK_SUPPORT)
  printf("  --no-hash-recalc                                      Skip recalculation of hashes on repacking\n");
  printf("  --no-elf-repack                                       Skip ELFs repacking\n");
#endif
  printf("  --decrypt-elfs                                        On unpack: decrypt/unfself every SELF/SPRX to plaintext ELF\n");
  printf("  --downgrade                                           On unpack: downgrade decrypted ELFs (needs --sdk-version)\n");
  printf("  --rewrap-fself                                        On unpack: re-wrap plaintext ELFs into fake selfs (after --downgrade)\n");
  printf("  --paid <hex/dec>                                      make-fself: program authentication id (default 0x3100000000000002)\n");
  printf("  --ptype <type|number>                                 make-fself: program type {fake,npdrm_exec,npdrm_dynlib,system_exec,system_dynlib,host_kernel,secure_module,secure_kernel} (default fake)\n");
  printf("  --app-version <hex/dec>                               make-fself: application version (default 0)\n");
  printf("  --fw-version <hex/dec>                                make-fself: firmware version (default 0)\n");
  printf("  --auth-info <0x88 bytes hex>                          make-fself: authentication info blob (default none)\n");
  printf("  --dump-sfo                                            Dump SFO structure from PKG file\n");
  printf("  --backport                                            Downgrade param.sfo SDK version (on unpack, or with --dump-sfo)\n");
  printf("  --sdk-version <8 hex digits>                          SDK version for --backport/--downgrade/-G (e.g. 05050000)\n");
  printf("  --dump-playgo                                         Dump Playgo structure from PKG file\n");
#if defined(ENABLE_EKC_KEYGEN)
  printf("  --dump-final-keys                                     Dump final keys to use with the tool\n");
#endif
#if defined(ENABLE_SD_KEYGEN)
  printf("  --dump-sd-info                                        Dump SD info\n");
#endif
  printf("  --use-random-passcode                                 Use random passcode for GP4 project\n");
  printf("  --all-compressed                                      Use compression for all files in GP4 project\n");
  printf("\n");
}

static void cleanup(void) {
  if (s_pkg)
    pkg_free(s_pkg);
  if (s_pfs)
    pfs_free(s_pfs);

  if (s_key_content_id)
    free(s_key_content_id);
  if (s_sdk_version)
    free(s_sdk_version);
  if (s_mkfs_auth_info)
    free(s_mkfs_auth_info);
#if defined(ENABLE_REPACK_SUPPORT)
  if (s_content_id)
    free(s_content_id);
#endif
  if (s_passcode)
    free(s_passcode);
#ifdef ENABLE_SD_KEYGEN
  if (s_sealed_key_file)
    free(s_sealed_key_file);
#endif
  if (s_encdec_tweak_key)
    free(s_encdec_tweak_key);
  if (s_encdec_data_key)
    free(s_encdec_data_key);
  if (s_sign_key)
    free(s_sign_key);
  if (s_sc0_key)
    free(s_sc0_key);
  if (s_meta_data_in_file)
    free(s_meta_data_in_file);
  if (s_meta_data_out_file)
    free(s_meta_data_out_file);
  if (s_pfs_image_data_file)
    free(s_pfs_image_data_file);
  if (s_gp4_file)
    free(s_gp4_file);
  if (s_file_paths)
    utarray_free(s_file_paths);

  if (s_input_file_path)
    free(s_input_file_path);
#if defined(ENABLE_REPACK_SUPPORT)
  if (s_plaintext_elf_directory)
    free(s_plaintext_elf_directory);
#endif
  if (s_output_file_path)
    free(s_output_file_path);

  keymgr_finalize();
  crypto_finalize();
}

static int pfs_get_size_cb(void* arg, uint64_t* size) {
  struct pfs_io_context* ctx = (struct pfs_io_context*)arg;

  assert(ctx != NULL);

  if (size)
    *size = ctx->map->size;

  return 1;
}

static int pfs_get_outer_location_cb(void* arg, uint64_t offset, uint64_t* outer_offset) {
  struct pfs_io_context* ctx = (struct pfs_io_context*)arg;

  assert(ctx != NULL);

  if (offset > ctx->map->size)
    return 0;

  if (outer_offset)
    *outer_offset = offset;

  return 1;
}

static int pfs_get_offset_size_cb(void* arg, uint64_t data_size, uint64_t* real_offset, uint64_t* size_to_read, int* compressed) {
  struct pfs_io_context* ctx = (struct pfs_io_context*)arg;

  assert(ctx != NULL);

  if (ctx->offset + data_size > ctx->map->size)
    return 0;

  if (real_offset)
    *real_offset = ctx->offset;

  if (size_to_read)
    *size_to_read = data_size;

  if (compressed)
    *compressed = 0;

  return 1;
}

static int pfs_seek_cb(void* arg, uint64_t offset) {
  struct pfs_io_context* ctx = (struct pfs_io_context*)arg;

  assert(ctx != NULL);

  if (offset > ctx->map->size)
    return 0;

  ctx->offset = offset;

  return 1;
}

static int pfs_read_cb(void* arg, void* data, uint64_t data_size) {
  struct pfs_io_context* ctx = (struct pfs_io_context*)arg;

  assert(ctx != NULL);
  assert(data != NULL);

  if (ctx->offset + data_size > ctx->map->size)
    return 0;

  memcpy(data, ctx->map->data + ctx->offset, data_size);

  return 1;
}

static int pfs_write_cb(void* arg, void* data, uint64_t data_size) {
  struct pfs_io_context* ctx = (struct pfs_io_context*)arg;

  assert(ctx != NULL);
  assert(data != NULL);

  if (ctx->offset + data_size > ctx->map->size)
    return 0;

  memcpy(ctx->map->data + ctx->offset, data, data_size);

  return 1;
}

static int pfs_can_seek_cb(void* arg, uint64_t offset) {
  struct pfs_io_context* ctx = (struct pfs_io_context*)arg;

  assert(ctx != NULL);

  if (offset > ctx->map->size)
    return 0;

  return 1;
}

static int pfs_can_read_cb(void* arg, uint64_t data_size) {
  struct pfs_io_context* ctx = (struct pfs_io_context*)arg;

  assert(ctx != NULL);

  if (ctx->offset + data_size > ctx->map->size)
    return 0;

  return 1;
}

static int pfs_can_write_cb(void* arg, uint64_t data_size) {
  struct pfs_io_context* ctx = (struct pfs_io_context*)arg;

  assert(ctx != NULL);

  if (ctx->offset + data_size > ctx->map->size)
    return 0;

  return 1;
}
