/*
 * PS4 SELF/SPRX decryption (retail x86-64).
 *
 * Port of flatz's self_tool4.py, built on the SELF/ELF parsing in self.hpp and
 * the crypto primitives in crypto.hpp (AES-CBC-CTS, HMAC-SHA256, RSA, zlib).
 * Root keys come from the config [self_keys] section (keys.h g_self_root_keys).
 *
 * Key selection (resolves the original tool's TODOs at lines 409/943 and the
 * "7 zero bytes" FIXME at 955): instead of a heuristic, each candidate key
 * decrypts the metadata and the RSA signature is verified with that key
 * generation's public key. The generation+index whose signature validates is
 * the correct key, determined cryptographically.
 */

#include "selfdecrypt.hpp"
#include "self.hpp"
#include "keys.h"
#include "crypto.hpp"
#include "util.h"

#include <zlib.h>

#define SELF_MACHINE_X86_64 0x3E
#define META_ENTRY_SIZE     0x50

/* Field offsets inside a decrypted metadata entry. */
#define META_OFF_DATA_KEY   0x00
#define META_OFF_DATA_IV    0x10
#define META_OFF_DIGEST     0x20
#define META_OFF_DIGEST_KEY 0x40

struct seg_data {
  uint8_t* data;
  size_t size;
  int done;
};

static uint8_t* read_whole_file(const char* path, size_t* out_size) {
  FILE* fp = fopen(path, "rb");
  uint8_t* buf = NULL;
  long sz;
  if (!fp)
    return NULL;
  if (fseek(fp, 0, SEEK_END) != 0)
    goto error;
  sz = ftell(fp);
  if (sz < 0)
    goto error;
  if (fseek(fp, 0, SEEK_SET) != 0)
    goto error;
  buf = (uint8_t*)malloc((size_t)sz ? (size_t)sz : 1);
  if (!buf)
    goto error;
  if ((size_t)sz > 0 && fread(buf, 1, (size_t)sz, fp) != (size_t)sz)
    goto error;
  fclose(fp);
  *out_size = (size_t)sz;
  return buf;
error:
  if (buf)
    free(buf);
  if (fp)
    fclose(fp);
  return NULL;
}

/* SELF-level flags from the header ext_flags field (hdr->flags @0x1A). */
static int self_has_encryption(struct self* self) {
  return (LE16(self->hdr->flags) & (1u << 1)) != 0;
}
static int self_has_signing(struct self* self) {
  return (LE16(self->hdr->flags) & (1u << 4)) == 0;
}

/* Find the block-table entry that describes the given data segment: the
   block-table entry (has_digests/has_extents) whose segment_index equals the
   data segment's own table index. (self_find_linked_entry can't be used: it
   returns the first entry matching the index without requiring it to be a
   block table, which picks a sibling data segment when indices collide.) */
static struct self_entry* find_block_table_entry(struct self* self, struct self_entry* seg, size_t* bt_index) {
  size_t target = (size_t)(seg - self->entry_table);
  size_t i;
  for (i = 0; i < self->entry_count; ++i) {
    struct self_entry* e = self->entry_table + i;
    if (self_entry_is_block_table_segment(e) && self_entry_segment_index(e) == target) {
      if (bt_index)
        *bt_index = i;
      return e;
    }
  }
  return NULL;
}

/* Find the data segment (has_blocks) whose ELF phdr index equals phdr_idx. */
static struct self_entry* find_segment_for_phdr(struct self* self, size_t phdr_idx, size_t* out_index) {
  size_t i;
  for (i = 0; i < self->entry_count; ++i) {
    struct self_entry* e = self->entry_table + i;
    if (self_entry_has_blocks(e) && self_entry_segment_index(e) == phdr_idx) {
      if (out_index)
        *out_index = i;
      return e;
    }
  }
  return NULL;
}

static const uint8_t* meta_entry_ptr(const uint8_t* meta_data, size_t idx) {
  return meta_data + idx * META_ENTRY_SIZE;
}

/*
 * Select and decrypt the metadata: try every configured (generation, index)
 * key, and accept the one whose RSA signature verifies. On success fills
 * meta_plain (meta_size bytes, caller-provided) and returns 1.
 */
/* Format a SELF version field (BCD nibbles) like self_tool4.py parse_version_64. */
static void self_format_version(uint64_t v, char* buf, size_t bufsz) {
  unsigned major = (unsigned)(((v >> 44) & 0xF) * 10 + ((v >> 40) & 0xF));
  unsigned minor = (unsigned)(((v >> 36) & 0xF) * 100 + ((v >> 32) & 0xF) * 10 + ((v >> 28) & 0xF));
  unsigned build = (unsigned)(((v >> 20) & 0xF) * 100 + ((v >> 16) & 0xF) * 10 + ((v >> 12) & 0xF));
  snprintf(buf, bufsz, "%02u.%03u.%03u", major, minor, build);
}

static int decrypt_and_verify_meta(struct self* self, const uint8_t* meta_enc, size_t meta_size, uint8_t* meta_plain) {
  size_t header_size = LE16(self->hdr->header_size);
  size_t meta_data_size = meta_size - SELF_SIGNATURE_SIZE;
  uint8_t* sig_data = NULL;
  int gen, i, found = 0;

  sig_data = (uint8_t*)malloc(header_size + meta_data_size);
  if (!sig_data)
    return 0;

  g_rsa_verify_quiet = 1; /* misses are expected while probing candidate keys */
  for (gen = 0; gen < SELF_ROOT_KEY_TYPE_COUNT && !found; ++gen) {
    struct self_root_keyset* ks = &g_self_root_keys[gen];
    if (!check_rsa_key_filled(&ks->rsa, 0))
      continue;
    for (i = 0; (size_t)i < ks->key_count; ++i) {
      uint8_t iv[SELF_ROOT_AES_KEY_SIZE];
      const uint8_t* sig;

      memcpy(iv, ks->aes_iv[i], sizeof(iv));
      if (!aes_decrypt_cbc_cts(ks->aes_key[i], SELF_ROOT_AES_KEY_SIZE, iv, meta_enc, meta_plain, meta_size))
        continue;

      /* sig_data = header || meta_data (decrypted meta minus the 0x100 signature) */
      memcpy(sig_data, self->data, header_size);
      memcpy(sig_data + header_size, meta_plain, meta_data_size);
      sig = meta_plain + meta_data_size;

      if (rsa_pkcsv15_verify(&ks->rsa, sig_data, header_size + meta_data_size, sig, SELF_SIGNATURE_SIZE)) {
        found = 1;
        break;
      }
    }
  }

  g_rsa_verify_quiet = 0;
  free(sig_data);
  return found;
}

/*
 * Decrypt a non-blocked segment (used for block-table segments and for plain
 * segments). Reads compressed_size bytes, verifies the HMAC digest, AES-CBC-CTS
 * decrypts, optionally inflates, and stores uncompressed_size bytes.
 */
static int decrypt_nonblocked_segment(struct self* self, size_t idx, const uint8_t* meta_data,
                                      int veri_after_dec, int skip_enc_check, struct seg_data* out) {
  struct self_entry* e = self->entry_table + idx;
  uint64_t seg_offset = LE64(e->offset);
  uint64_t mem_size = LE64(e->compressed_size);   /* on-disk size */
  uint64_t file_size = LE64(e->uncompressed_size); /* target size */
  int is_compressed = self_entry_is_compressed_segment(e);
  const uint8_t* meta = meta_entry_ptr(meta_data, idx);
  const uint8_t* digest = meta + META_OFF_DIGEST;
  const uint8_t* digest_key = meta + META_OFF_DIGEST_KEY;
  const uint8_t* data_key = meta + META_OFF_DATA_KEY;
  const uint8_t* data_iv = meta + META_OFF_DATA_IV;
  int seg_enc = self_entry_is_encrypted_segment(e);
  int seg_sig = self_entry_is_signed_segment(e);
  int do_sign = self_has_signing(self) && (self_has_signing(self) == seg_sig);
  int do_enc = skip_enc_check || (self_has_encryption(self) && (self_has_encryption(self) == seg_enc));
  uint8_t* buf = NULL;
  size_t read_size = (size_t)mem_size;
  size_t compressed_extra = 0; /* low-nibble padding trimmed before inflate */
  uint8_t computed[SELF_HASH_SIZE];
  uint8_t iv[SELF_ROOT_AES_KEY_SIZE];

  /* Compressed non-blocked segments store their on-disk size 16-byte aligned:
     read/decrypt only the aligned part, and inflate size&~0xF minus the low
     nibble (self_tool4.py _decrypt_nonblocked_segment). */
  if (is_compressed) {
    compressed_extra = read_size & 0xF;
    read_size &= ~(size_t)0xF;
  }

  if (seg_offset + read_size > self->size) {
    warning("SELF segment #%zu out of bounds.", idx);
    return 0;
  }
  buf = (uint8_t*)malloc(read_size ? read_size : 1);
  if (!buf)
    return 0;
  memcpy(buf, self->data + seg_offset, read_size);

  if (!veri_after_dec && do_sign) {
    hmac_sha256_buffer(digest_key, SELF_ROOT_AES_KEY_SIZE, buf, read_size, computed);
    if (memcmp(digest, computed, SELF_HASH_SIZE) != 0)
      warning("Wrong digest for SELF segment #%zu (continuing).", idx);
  }
  if (do_enc) {
    memcpy(iv, data_iv, sizeof(iv));
    if (!aes_decrypt_cbc_cts(data_key, SELF_ROOT_AES_KEY_SIZE, iv, buf, buf, read_size)) {
      free(buf);
      return 0;
    }
  }
  if (veri_after_dec && do_sign) {
    hmac_sha256_buffer(digest_key, SELF_ROOT_AES_KEY_SIZE, buf, read_size, computed);
    if (memcmp(digest, computed, SELF_HASH_SIZE) != 0)
      warning("Wrong digest for SELF segment #%zu (continuing).", idx);
  }

  if (is_compressed) {
    uLongf out_len = (uLongf)file_size;
    uint8_t* dec = (uint8_t*)malloc(file_size ? (size_t)file_size : 1);
    if (!dec) { free(buf); return 0; }
    if (uncompress(dec, &out_len, buf, (uLong)(read_size - compressed_extra)) != Z_OK || out_len != file_size) {
      warning("Unable to decompress SELF segment #%zu.", idx);
      free(dec); free(buf);
      return 0;
    }
    free(buf);
    out->data = dec;
    out->size = (size_t)file_size;
  } else {
    if (read_size != file_size) {
      warning("Size mismatch for SELF segment #%zu.", idx);
      free(buf);
      return 0;
    }
    out->data = buf;
    out->size = read_size;
  }
  out->done = 1;
  return 1;
}

/*
 * Decrypt a blocked segment: decrypt its block-table segment first, then each
 * data block (HMAC-verified, AES-CBC-CTS decrypted, optionally inflated).
 * Only the non-compressed path is exercised by the eboot test; the compressed
 * (extent) path is ported faithfully but currently unvalidated.
 */
static int decrypt_blocked_segment(struct self* self, size_t idx, const uint8_t* meta_data,
                                   int veri_after_dec, int skip_enc_check,
                                   struct seg_data* segs) {
  struct self_entry* e = self->entry_table + idx;
  size_t bt_idx = 0;
  struct self_entry* bt;
  size_t block_size = self_entry_block_size(e);
  uint64_t file_size = LE64(e->uncompressed_size);
  uint64_t mem_size = LE64(e->compressed_size);
  size_t block_count = (size_t)((file_size + block_size - 1) / block_size);
  int has_digests, has_extents;
  size_t digests_size, extents_size;
  const uint8_t* meta = meta_entry_ptr(meta_data, idx);
  const uint8_t* digest_key = meta + META_OFF_DIGEST_KEY;
  const uint8_t* data_key = meta + META_OFF_DATA_KEY;
  const uint8_t* data_iv = meta + META_OFF_DATA_IV;
  int seg_enc = self_entry_is_encrypted_segment(e);
  int seg_sig = self_entry_is_signed_segment(e);
  int do_sign = self_has_signing(self) && (self_has_signing(self) == seg_sig);
  int do_enc = skip_enc_check || (self_has_encryption(self) && (self_has_encryption(self) == seg_enc));
  int is_compressed = self_entry_is_compressed_segment(e);
  uint64_t seg_offset = LE64(e->offset);
  uint8_t* out = NULL;
  size_t out_size = 0, out_cap = 0;
  const uint8_t* bt_data;
  size_t i;
  int status = 0;

  bt = find_block_table_entry(self, e, &bt_idx);
  if (!bt) {
    warning("No block table for SELF segment #%zu.", idx);
    return 0;
  }
  if (self_entry_is_compressed_segment(bt)) {
    warning("Compressed block table not supported (segment #%zu).", idx);
    return 0;
  }
  has_digests = self_entry_has_digests(bt);
  has_extents = self_entry_has_extents(bt);
  digests_size = has_digests ? block_count * SELF_HASH_SIZE : 0;
  extents_size = has_extents ? block_count * SELF_SEGMENT_BLOCK_EXTENT_SIZE : 0;

  /* Decrypt the block table segment. */
  if (!segs[bt_idx].done) {
    if (!decrypt_nonblocked_segment(self, bt_idx, meta_data, veri_after_dec, skip_enc_check, &segs[bt_idx]))
      return 0;
  }
  bt_data = segs[bt_idx].data;
  if (segs[bt_idx].size != digests_size + extents_size) {
    warning("Unexpected block table size for SELF segment #%zu.", idx);
    return 0;
  }

  out_cap = (size_t)file_size + block_size;
  out = (uint8_t*)malloc(out_cap ? out_cap : 1);
  if (!out)
    return 0;

  if (is_compressed) {
    const uint8_t* extents = bt_data + digests_size;
    uint64_t total = 0;
    for (i = 0; i < block_count; ++i) {
      uint32_t ext_offset = LE32(*(const uint32_t*)(extents + i * SELF_SEGMENT_BLOCK_EXTENT_SIZE));
      uint32_t ext_size = LE32(*(const uint32_t*)(extents + i * SELF_SEGMENT_BLOCK_EXTENT_SIZE + 4));
      uint64_t block_idx_offset = ext_offset & ~((uint32_t)block_size - 1);
      uint32_t block_offset = ext_offset & ((uint32_t)block_size - 1);
      uint64_t cur_size = ext_size & ~0xFu;
      int blk_compressed;
      uint8_t* blk;

      if (cur_size == 0) {
        block_idx_offset = (uint64_t)i * block_size;
        cur_size = (block_idx_offset + block_size <= file_size) ? block_size : (file_size - block_idx_offset);
      } else if ((uint64_t)i * block_size + ext_size == file_size) {
        cur_size = ext_size;
      }
      blk_compressed = (ext_size != block_size) && ((uint64_t)i * block_size + ext_size != file_size);
      (void)block_offset;

      if (seg_offset + ext_offset + cur_size > self->size) { warning("Block OOB seg #%zu.", idx); goto done; }
      blk = (uint8_t*)malloc((size_t)cur_size ? (size_t)cur_size : 1);
      if (!blk) goto done;
      memcpy(blk, self->data + seg_offset + ext_offset, (size_t)cur_size);

      if (do_sign && has_digests) {
        uint8_t computed[SELF_HASH_SIZE];
        hmac_sha256_buffer(digest_key, SELF_ROOT_AES_KEY_SIZE, blk, (size_t)cur_size, computed);
        if (memcmp(bt_data + i * SELF_HASH_SIZE, computed, SELF_HASH_SIZE) != 0)
          warning("Wrong block digest seg #%zu block %zu (continuing).", idx, i);
      }
      if (do_enc) {
        uint8_t iv[SELF_ROOT_AES_KEY_SIZE];
        memcpy(iv, data_iv, sizeof(iv));
        if (!aes_decrypt_cbc_cts(data_key, SELF_ROOT_AES_KEY_SIZE, iv, blk, blk, (size_t)cur_size)) { free(blk); goto done; }
      }
      if (blk_compressed) {
        uLongf dlen = (uLongf)block_size;
        if (out_size + block_size > out_cap) { free(blk); goto done; }
        if (uncompress(out + out_size, &dlen, blk, (uLong)cur_size) != Z_OK) { warning("Inflate fail seg #%zu blk %zu.", idx, i); free(blk); goto done; }
        out_size += dlen;
      } else {
        if (out_size + cur_size > out_cap) { free(blk); goto done; }
        memcpy(out + out_size, blk, (size_t)cur_size);
        out_size += (size_t)cur_size;
      }
      total += cur_size;
      free(blk);
    }
    if (total != mem_size)
      warning("Compressed size mismatch seg #%zu.", idx);
  } else {
    uint64_t size_left = file_size;
    for (i = 0; i < block_count && size_left > 0; ++i) {
      size_t cur_size = (block_size < size_left) ? block_size : (size_t)size_left;
      uint8_t* blk = out + out_size;

      if (seg_offset + (uint64_t)i * block_size + cur_size > self->size) { warning("Block OOB seg #%zu.", idx); goto done; }
      memcpy(blk, self->data + seg_offset + (uint64_t)i * block_size, cur_size);

      if (do_sign && has_digests) {
        uint8_t computed[SELF_HASH_SIZE];
        hmac_sha256_buffer(digest_key, SELF_ROOT_AES_KEY_SIZE, blk, cur_size, computed);
        if (memcmp(bt_data + i * SELF_HASH_SIZE, computed, SELF_HASH_SIZE) != 0)
          warning("Wrong block digest seg #%zu block %zu (continuing).", idx, i);
      }
      if (do_enc) {
        uint8_t iv[SELF_ROOT_AES_KEY_SIZE];
        memcpy(iv, data_iv, sizeof(iv));
        if (!aes_decrypt_cbc_cts(data_key, SELF_ROOT_AES_KEY_SIZE, iv, blk, blk, cur_size)) goto done;
      }
      out_size += cur_size;
      size_left -= cur_size;
    }
  }

  segs[idx].data = out;
  segs[idx].size = out_size;
  segs[idx].done = 1;
  out = NULL;
  status = 1;

done:
  if (out)
    free(out);
  return status;
}

static int build_elf(struct self* self, const struct seg_data* segs,
                     const uint8_t* extra_data, size_t extra_size,
                     uint8_t** out_elf, size_t* out_elf_size) {
  struct elf* elf = self->elf;
  size_t phnum = LE16(elf->ehdr->e_phnum);
  size_t phentsize = LE16(elf->ehdr->e_phentsize);
  uint64_t phoff = LE64(elf->ehdr->e_phoff);
  size_t header_end = (size_t)(phoff + phnum * phentsize);
  uint64_t total = header_end;
  uint8_t* buf;
  size_t i;

  /* Compute output size = furthest segment end. */
  for (i = 0; i < phnum; ++i) {
    struct elf64_phdr* ph = elf->phdrs + i;
    uint32_t type = LE32(ph->p_type);
    uint64_t end = LE64(ph->p_offset) + LE64(ph->p_filesz);
    if (type == ELF_PT_SCE_VERSION || type == ELF_PT_LOAD ||
        type == 0x61000000 || type == 0x61000010 || type == 0x6FFFFF00) {
      if (end > total)
        total = end;
    }
  }

  buf = (uint8_t*)malloc((size_t)total ? (size_t)total : 1);
  if (!buf)
    return 0;
  memset(buf, 0, (size_t)total);
  memcpy(buf, elf->data, header_end);

  for (i = 0; i < phnum; ++i) {
    struct elf64_phdr* ph = elf->phdrs + i;
    uint32_t type = LE32(ph->p_type);
    uint64_t off = LE64(ph->p_offset);
    uint64_t fsz = LE64(ph->p_filesz);
    const uint8_t* src = NULL;
    size_t src_size = 0;

    if (type == ELF_PT_SCE_VERSION) {
      src = extra_data;
      src_size = extra_size;
    } else if (type == ELF_PT_LOAD || type == 0x61000000 || type == 0x61000010 || type == 0x6FFFFF00) {
      size_t seg_idx;
      struct self_entry* seg = find_segment_for_phdr(self, i, &seg_idx);
      if (!seg || !segs[seg_idx].done)
        continue;
      src = segs[seg_idx].data;
      src_size = segs[seg_idx].size;
    } else {
      continue;
    }
    if (!src || src_size != fsz) {
      warning("SELF phdr #%zu size mismatch (have %zu, want %ju).", i, src_size, (uintmax_t)fsz);
      free(buf);
      return 0;
    }
    if (off + fsz > total) {
      free(buf);
      return 0;
    }
    memcpy(buf + off, src, (size_t)fsz);
  }

  *out_elf = buf;
  *out_elf_size = (size_t)total;
  return 1;
}

int self_decrypt_buffer(const void* self_data, size_t self_size, uint8_t** out_elf, size_t* out_elf_size) {
  struct self* self = NULL;
  struct seg_data* segs = NULL;
  uint8_t* meta_plain = NULL;
  const uint8_t* extra_data = NULL;
  size_t extra_size = 0;
  size_t header_size, meta_size, meta_data_size;
  const uint8_t* meta_enc;
  int is_finalized, veri_after_dec, skip_enc_check;
  uint64_t paid, ptype;
  size_t i;
  int status = 0;

  self = self_alloc((void*)self_data, self_size);
  if (!self)
    return 0;

  if (LE16(self->elf->ehdr->e_machine) != SELF_MACHINE_X86_64) {
    warning("Only x86-64 SELF decryption is supported.");
    goto error;
  }

  header_size = LE16(self->hdr->header_size);
  meta_size = LE16(self->hdr->meta_size);
  if (header_size + meta_size > self_size || meta_size < SELF_SIGNATURE_SIZE) {
    warning("Invalid SELF header/meta size.");
    goto error;
  }
  meta_enc = self->data + header_size;
  meta_data_size = meta_size - SELF_SIGNATURE_SIZE;

  paid = LE64(self->ex_info->paid);
  ptype = LE64(self->ex_info->ptype);
  is_finalized = (ptype != SELF_PTYPE_FAKE);
  veri_after_dec = (paid == U64C(0x3F00000000000001) || paid == U64C(0x3C00000000000001));
  skip_enc_check = (paid == U64C(0x3C00000000000001));

  segs = (struct seg_data*)calloc(self->entry_count, sizeof(*segs));
  if (!segs)
    goto error;

  if (is_finalized) {
    meta_plain = (uint8_t*)malloc(meta_size);
    if (!meta_plain)
      goto error;
    if (!decrypt_and_verify_meta(self, meta_enc, meta_size, meta_plain)) {
      char fwbuf[16], appbuf[16];
      self_format_version(LE64(self->ex_info->fw_version), fwbuf, sizeof(fwbuf));
      self_format_version(LE64(self->ex_info->app_version), appbuf, sizeof(appbuf));
      warning("No matching SELF root key in the keyset for this binary "
              "(fw %s, app %s, ptype 0x%" PRIX64 ", paid 0x%016" PRIX64 "). "
              "Its root key is not in the [self_keys] config — likely a newer firmware than the known keyset covers.",
              fwbuf, appbuf, ptype, paid);
      goto error;
    }

    /* Decrypt every data segment (block tables are pulled in on demand). */
    for (i = 0; i < self->entry_count; ++i) {
      struct self_entry* e = self->entry_table + i;
      if (self_entry_is_block_table_segment(e))
        continue;
      if (self_entry_has_blocks(e)) {
        if (!decrypt_blocked_segment(self, i, meta_plain, veri_after_dec, skip_enc_check, segs))
          goto error;
      } else {
        if (!decrypt_nonblocked_segment(self, i, meta_plain, veri_after_dec, skip_enc_check, &segs[i]))
          goto error;
      }
    }
  } else {
    warning("SELF is fake-signed; nothing to decrypt.");
    goto error;
  }

  /* PT_SCE_VERSION extra data lives right after total_size. */
  {
    size_t phnum = LE16(self->elf->ehdr->e_phnum);
    for (i = 0; i < phnum; ++i) {
      struct elf64_phdr* ph = self->elf->phdrs + i;
      if (LE32(ph->p_type) == ELF_PT_SCE_VERSION) {
        uint64_t off = LE64(self->hdr->file_size);
        uint64_t sz = LE64(ph->p_filesz);
        if (off + sz <= self_size) {
          extra_data = self->data + off;
          extra_size = (size_t)sz;
        }
        break;
      }
    }
  }

  if (!build_elf(self, segs, extra_data, extra_size, out_elf, out_elf_size))
    goto error;

  status = 1;

error:
  if (segs) {
    for (i = 0; i < self->entry_count; ++i)
      if (segs[i].data)
        free(segs[i].data);
    free(segs);
  }
  if (meta_plain)
    free(meta_plain);
  if (self)
    self_free(self);
  return status;
}

int self_decrypt_file(const char* self_path, const char* elf_path) {
  uint8_t* self_data = NULL;
  uint8_t* elf_data = NULL;
  size_t self_size = 0, elf_size = 0;
  FILE* fp = NULL;
  int status = 0;

  self_data = read_whole_file(self_path, &self_size);
  if (!self_data) {
    warning("Unable to read SELF file: %s", self_path);
    goto done;
  }
  if (!self_decrypt_buffer(self_data, self_size, &elf_data, &elf_size))
    goto done;

  fp = fopen(elf_path, "wb");
  if (!fp || (elf_size > 0 && fwrite(elf_data, 1, elf_size, fp) != elf_size)) {
    warning("Unable to write ELF file: %s", elf_path);
    goto done;
  }
  status = 1;

done:
  if (fp)
    fclose(fp);
  if (elf_data)
    free(elf_data);
  if (self_data)
    free(self_data);
  return status;
}
