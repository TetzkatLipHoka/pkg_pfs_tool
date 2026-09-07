/*
 * make_fself — wrap a plaintext ELF into a fake-signed SELF.
 * Port of flatz's make_fself3.py, built on elf_alloc + self.hpp packed structs.
 * Host is little-endian and the tool is x86-only, so the LE* macros are identity
 * and the SELF/ELF packed structs lay out byte-for-byte like the reference's
 * '<...' struct.pack formats.
 */

#include "makefself.hpp"
#include "self.hpp"
#include "crypto.hpp"
#include "util.h"

#define MKFS_BLOCK_SIZE      0x4000
#define MKFS_DIGEST_SIZE     0x20
#define MKFS_SIGNATURE_SIZE  0x100
#define MKFS_KEY_TYPE        0x101
#define MKFS_AUTH_INFO_SIZE  0x88

/* self_entry.flags bit layout (see union self_entry_flags in self.hpp). */
#define MKFS_FLAG_SIGNED     (U64C(1) << 2)
#define MKFS_FLAG_HAS_BLOCKS (U64C(1) << 11)
#define MKFS_FLAG_HAS_DIGESTS (U64C(1) << 16)
#define MKFS_FLAG_BLOCK_SIZE_SHIFT 12
#define MKFS_FLAG_SEGMENT_IDX_SHIFT 20

/* ilog2(0x4000) - 12 == 2; the block_size field for a 0x4000 block. */
#define MKFS_BLOCK_SIZE_FIELD U64C(2)

struct mkfs_entry {
  uint64_t props;
  uint64_t offset;
  uint64_t filesz;
  uint64_t memsz;
  const uint8_t* data; /* NULL for meta entries (all-zero digests) */
};

void makefself_opts_default(struct makefself_opts* opts) {
  if (!opts)
    return;
  opts->paid = U64C(0x3100000000000002);
  opts->ptype = SELF_PTYPE_FAKE;
  opts->app_version = 0;
  opts->fw_version = 0;
  opts->auth_info = NULL;
}

static int mkfs_segment_gets_entry(uint32_t type) {
  switch (type) {
    case ELF_PT_LOAD:
    case ELF_PT_SCE_RELRO:
    case ELF_PT_SCE_DYNLIBDATA:
    case ELF_PT_SCE_COMMENT:
      return 1;
    default:
      return 0;
  }
}

int self_make_fself_buffer(const void* elf_data, size_t elf_size, const struct makefself_opts* opts_in, uint8_t** out_self, size_t* out_self_size) {
  struct makefself_opts opts;
  struct elf* elf = NULL;
  struct mkfs_entry* entries = NULL;
  uint8_t* buf = NULL;
  size_t phnum, phentsize, ehsize, i, num_entries = 0, entry_idx;
  uint64_t phoff, elf_hdr_unaligned, elf_header_size;
  uint64_t header_size, meta_size, offset, file_size, elf_offset, ex_info_off, npdrm_off, meta_footer_off, version_pos, total;
  const uint8_t* version_data = NULL;
  uint64_t version_len = 0;
  uint16_t e_type, e_machine;
  int status = 0;

  makefself_opts_default(&opts);
  if (opts_in)
    opts = *opts_in;

  elf = elf_alloc((void*)elf_data, elf_size, /*is_inner=*/1);
  if (!elf)
    return -1;

  e_type = ELF64_HALF_LE(elf->ehdr->e_type);
  e_machine = ELF64_HALF_LE(elf->ehdr->e_machine);
  if (e_machine != 0x3E) { /* EM_X86_64 */
    warning("make_fself: unsupported machine 0x%X (x86-64 only).", e_machine);
    goto out;
  }
  if (e_type != ELF_ET_EXEC && e_type != ELF_ET_SCE_EXEC && e_type != ELF_ET_SCE_EXEC_ASLR && e_type != ELF_ET_SCE_DYNAMIC) {
    warning("make_fself: unsupported ELF type 0x%X.", e_type);
    goto out;
  }

  phnum = ELF64_HALF_LE(elf->ehdr->e_phnum);
  phentsize = ELF64_HALF_LE(elf->ehdr->e_phentsize);
  ehsize = ELF64_HALF_LE(elf->ehdr->e_ehsize);
  phoff = ELF64_OFF_LE(elf->ehdr->e_phoff);

  if (phoff + phnum * phentsize > elf_size) {
    warning("make_fself: ELF program header table out of bounds.");
    goto out;
  }

  /* Pass 1: build the entry list (meta + data per qualifying segment) and grab
     the version segment body. */
  entries = (struct mkfs_entry*)calloc((phnum ? phnum : 1) * 2, sizeof(*entries));
  if (!entries)
    goto out;
  entry_idx = 0;
  for (i = 0; i < phnum; ++i) {
    struct elf64_phdr* ph = elf->phdrs + i;
    uint32_t ptype = ELF64_WORD_LE(ph->p_type);
    if (ptype == ELF_PT_SCE_VERSION) {
      version_data = elf->data + ELF64_OFF_LE(ph->p_offset);
      version_len = ELF64_XWORD_LE(ph->p_filesz);
    }
    if (!mkfs_segment_gets_entry(ptype))
      continue;
    /* meta entry: signed + has_digests, segment_index = entry_idx + 1 */
    entries[entry_idx].props = MKFS_FLAG_SIGNED | MKFS_FLAG_HAS_DIGESTS |
      ((uint64_t)(entry_idx + 1) << MKFS_FLAG_SEGMENT_IDX_SHIFT);
    /* data entry: signed + has_blocks + block_size(0x4000), segment_index = i */
    entries[entry_idx + 1].props = MKFS_FLAG_SIGNED | MKFS_FLAG_HAS_BLOCKS |
      (MKFS_BLOCK_SIZE_FIELD << MKFS_FLAG_BLOCK_SIZE_SHIFT) |
      ((uint64_t)i << MKFS_FLAG_SEGMENT_IDX_SHIFT);
    entry_idx += 2;
  }
  num_entries = entry_idx;

  elf_hdr_unaligned = MAX((uint64_t)ehsize, phoff + phnum * phentsize);
  elf_header_size = align_up_64(elf_hdr_unaligned, 16);

  header_size = SELF_HEADER_SIZE + num_entries * SELF_ENTRY_SIZE + elf_hdr_unaligned;
  header_size = align_up_64(header_size, 16);
  header_size += SELF_EXTENDED_INFO_SIZE;         /* ex_info */
  header_size += SELF_NPDRM_CONTROL_BLOCK_SIZE;   /* HAS_NPDRM */

  meta_size = num_entries * SELF_META_BLOCK_SIZE + SELF_META_FOOTER_SIZE;

  if (header_size > 0xFFFF || meta_size > 0xFFFF) {
    warning("make_fself: header/meta size overflow (too many segments).");
    goto out;
  }

  /* Pass 2: assign segment offsets. */
  offset = header_size + meta_size;
  entry_idx = 0;
  for (i = 0; i < phnum; ++i) {
    struct elf64_phdr* ph = elf->phdrs + i;
    uint64_t filesz, num_blocks;
    if (!mkfs_segment_gets_entry(ELF64_WORD_LE(ph->p_type)))
      continue;
    filesz = ELF64_XWORD_LE(ph->p_filesz);

    num_blocks = align_up_64(filesz, MKFS_BLOCK_SIZE) / MKFS_BLOCK_SIZE;
    entries[entry_idx].offset = offset;
    entries[entry_idx].filesz = entries[entry_idx].memsz = MKFS_DIGEST_SIZE * num_blocks;
    entries[entry_idx].data = NULL; /* zeroed digests */
    offset += entries[entry_idx].filesz;
    offset = align_up_64(offset, 16);

    entries[entry_idx + 1].offset = offset;
    entries[entry_idx + 1].filesz = entries[entry_idx + 1].memsz = filesz;
    entries[entry_idx + 1].data = elf->data + ELF64_OFF_LE(ph->p_offset);
    offset += filesz;
    offset = align_up_64(offset, 16);

    entry_idx += 2;
  }
  file_size = offset;

  /* Version data is written right after the last segment (unaligned), possibly
     past file_size — faithful to the reference. */
  version_pos = (num_entries > 0)
    ? entries[num_entries - 1].offset + entries[num_entries - 1].filesz
    : header_size + meta_size;
  total = file_size;
  if (version_data && version_pos + version_len > total)
    total = version_pos + version_len;

  buf = (uint8_t*)malloc((size_t)(total ? total : 1));
  if (!buf)
    goto out;
  memset(buf, 0, (size_t)total);

  /* Common + extended header (self_hdr covers both, 0x20 bytes). */
  {
    struct self_hdr* h = (struct self_hdr*)buf;
    h->magic = SELF_MAGIC;
    h->version = SELF_VERSION;
    h->mode = SELF_MODE;
    h->endian = SELF_ENDIANNESS;
    h->attr = SELF_ATTRIBUTE;
    h->key_type = LE32(MKFS_KEY_TYPE);
    h->header_size = LE16((uint16_t)header_size);
    h->meta_size = LE16((uint16_t)meta_size);
    h->file_size = LE64(file_size);
    h->entry_count = LE16((uint16_t)num_entries);
    /* flags = 0x2 | (signed_block_count(2) << 4) = 0x22 */
    h->flags = LE16(0x22);
  }

  /* Entry table. */
  {
    struct self_entry* et = (struct self_entry*)(buf + SELF_HEADER_SIZE);
    for (i = 0; i < num_entries; ++i) {
      et[i].flags.bitmask = LE64(entries[i].props);
      et[i].offset = LE64(entries[i].offset);
      et[i].compressed_size = LE64(entries[i].filesz);
      et[i].uncompressed_size = LE64(entries[i].memsz);
    }
  }

  /* ELF headers: ehdr verbatim, then the phdr table at its file offset. */
  elf_offset = SELF_HEADER_SIZE + num_entries * SELF_ENTRY_SIZE;
  memcpy(buf + elf_offset, elf->data, ehsize);
  if (phnum > 0)
    memcpy(buf + elf_offset + phoff, elf->data + phoff, phnum * phentsize);

  /* Extended info. */
  ex_info_off = elf_offset + elf_header_size;
  {
    struct self_extended_info* ex = (struct self_extended_info*)(buf + ex_info_off);
    ex->paid = LE64(opts.paid);
    ex->ptype = LE64(opts.ptype);
    ex->app_version = LE64(opts.app_version);
    ex->fw_version = LE64(opts.fw_version);
    sha256_buffer(elf_data, elf_size, ex->file_hash);
  }

  /* NPDRM control block (type only; content id + pad zeroed). */
  npdrm_off = ex_info_off + SELF_EXTENDED_INFO_SIZE;
  {
    struct self_npdrm_control_block* np = (struct self_npdrm_control_block*)(buf + npdrm_off);
    np->type = LE16(SELF_CONTROL_BLOCK_NPDRM);
  }

  /* Meta blocks are all zero (already memset). Meta footer + signature. */
  meta_footer_off = header_size + num_entries * SELF_META_BLOCK_SIZE;
  {
    struct self_meta_footer* ft = (struct self_meta_footer*)(buf + meta_footer_off);
    ft->unk1 = LE32(0x10000);
    if (opts.auth_info) {
      /* signature = pack('<QQ', 0x88, paid) + auth_info[8:], zero-padded. */
      uint64_t* sig64 = (uint64_t*)ft->signature;
      sig64[0] = LE64(MKFS_AUTH_INFO_SIZE);
      sig64[1] = LE64(opts.paid);
      memcpy(ft->signature + 16, opts.auth_info + 8, MKFS_AUTH_INFO_SIZE - 8);
    }
  }

  /* Segment data. */
  for (i = 0; i < num_entries; ++i) {
    if (entries[i].data && entries[i].filesz > 0)
      memcpy(buf + entries[i].offset, entries[i].data, (size_t)entries[i].filesz);
  }

  /* Version segment body, appended verbatim. */
  if (version_data && version_len > 0)
    memcpy(buf + version_pos, version_data, (size_t)version_len);

  *out_self = buf;
  *out_self_size = (size_t)total;
  buf = NULL;
  status = 1;

out:
  if (buf)
    free(buf);
  if (entries)
    free(entries);
  if (elf)
    elf_free(elf);
  return status;
}

static uint8_t* mkfs_read_file(const char* path, size_t* out_size) {
  FILE* fp = fopen(path, "rb");
  uint8_t* buf = NULL;
  long sz;
  if (!fp)
    return NULL;
  if (fseek(fp, 0, SEEK_END) != 0 || (sz = ftell(fp)) < 0 || fseek(fp, 0, SEEK_SET) != 0)
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
  if (buf) free(buf);
  if (fp) fclose(fp);
  return NULL;
}

int self_make_fself_file(const char* elf_path, const char* self_path, const struct makefself_opts* opts) {
  uint8_t* elf_data = NULL;
  uint8_t* self_data = NULL;
  size_t elf_size = 0, self_size = 0;
  FILE* fp = NULL;
  int r, status = 0;

  elf_data = mkfs_read_file(elf_path, &elf_size);
  if (!elf_data) {
    warning("Unable to read ELF file: %s", elf_path);
    return -1;
  }
  r = self_make_fself_buffer(elf_data, elf_size, opts, &self_data, &self_size);
  if (r <= 0) {
    free(elf_data);
    return r;
  }

  fp = fopen(self_path, "wb");
  if (!fp || (self_size > 0 && fwrite(self_data, 1, self_size, fp) != self_size)) {
    warning("Unable to write SELF file: %s", self_path);
    status = -1;
    goto done;
  }
  status = 1;

done:
  if (fp) fclose(fp);
  free(self_data);
  free(elf_data);
  return status;
}
