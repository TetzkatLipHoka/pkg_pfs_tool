/*
 * unfself — extract the plaintext ELF from a fake-signed SELF.
 * Port of SocraticBliss's UnFSelf.py, built on self_alloc (self.hpp).
 */

#include "unfself.hpp"
#include "self.hpp"
#include "util.h"

struct unf_entry {
  const uint8_t* data;
  uint64_t len;
  int used;
};

int self_unfself_buffer(const void* self_data, size_t self_size, uint8_t** out_elf, size_t* out_elf_size) {
  struct self* self = NULL;
  struct elf* elf;
  struct unf_entry* entries = NULL;
  uint8_t* buf = NULL;
  size_t phnum, phent, i, p, n_entries = 0;
  uint64_t phoff, header_end, total, last_end;
  int status = 0;

  self = self_alloc((void*)self_data, self_size);
  if (!self)
    return -1;

  if (LE64(self->ex_info->ptype) != SELF_PTYPE_FAKE) {
    warning("Not a fake-signed self (ptype 0x%" PRIX64 "); use --decrypt-self instead.", LE64(self->ex_info->ptype));
    self_free(self);
    return 0;
  }

  elf = self->elf;
  phnum = LE16(elf->ehdr->e_phnum);
  phent = LE16(elf->ehdr->e_phentsize);
  phoff = LE64(elf->ehdr->e_phoff);
  header_end = phoff + (uint64_t)phnum * phent;
  if (header_end > elf->size) {
    warning("unfself: ELF header/phdr table out of bounds.");
    goto error;
  }

  /* Output size = furthest program-header file extent (and at least the header). */
  total = header_end;
  for (i = 0; i < phnum; ++i) {
    struct elf64_phdr* ph = elf->phdrs + i;
    uint64_t end = LE64(ph->p_offset) + LE64(ph->p_filesz);
    if (end > total)
      total = end;
  }

  /* Collect the plaintext segment blobs: one per SELF entry, plus the trailing
     data after the last entry (the SCE version segment). */
  entries = (struct unf_entry*)calloc(self->entry_count + 1, sizeof(*entries));
  if (!entries)
    goto error;
  for (i = 0; i < self->entry_count; ++i) {
    uint64_t off = LE64(self->entry_table[i].offset);
    uint64_t len = LE64(self->entry_table[i].compressed_size);
    if (off > self_size)
      off = self_size;
    if (off + len > self_size)
      len = self_size - off;
    entries[n_entries].data = self->data + off;
    entries[n_entries].len = len;
    ++n_entries;
  }
  last_end = 0;
  if (self->entry_count > 0) {
    struct self_entry* le = self->entry_table + (self->entry_count - 1);
    last_end = LE64(le->offset) + LE64(le->compressed_size);
  }
  if (last_end < self_size) {
    entries[n_entries].data = self->data + last_end;
    entries[n_entries].len = self_size - last_end;
    ++n_entries;
  }

  buf = (uint8_t*)malloc((size_t)total ? (size_t)total : 1);
  if (!buf)
    goto error;
  memset(buf, 0, (size_t)total);
  memcpy(buf, elf->data, (size_t)header_end);

  /* Place each blob at the first unused program header whose file size matches. */
  for (p = 0; p < phnum; ++p) {
    struct elf64_phdr* ph = elf->phdrs + p;
    uint64_t poff = LE64(ph->p_offset);
    uint64_t pfsz = LE64(ph->p_filesz);
    if (pfsz == 0)
      continue;
    for (i = 0; i < n_entries; ++i) {
      if (!entries[i].used && entries[i].len == pfsz) {
        if (poff + pfsz <= total)
          memcpy(buf + poff, entries[i].data, (size_t)pfsz);
        entries[i].used = 1;
        break;
      }
    }
  }

  *out_elf = buf;
  *out_elf_size = (size_t)total;
  buf = NULL;
  status = 1;

error:
  if (buf)
    free(buf);
  if (entries)
    free(entries);
  if (self)
    self_free(self);
  return status;
}

static uint8_t* unf_read_file(const char* path, size_t* out_size) {
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

int self_unfself_file(const char* self_path, const char* elf_path) {
  uint8_t* self_data = NULL;
  uint8_t* elf_data = NULL;
  size_t self_size = 0, elf_size = 0;
  FILE* fp = NULL;
  int r, status = 0;

  self_data = unf_read_file(self_path, &self_size);
  if (!self_data) {
    warning("Unable to read self file: %s", self_path);
    return -1;
  }
  r = self_unfself_buffer(self_data, self_size, &elf_data, &elf_size);
  if (r <= 0) {
    free(self_data);
    return r;
  }

  fp = fopen(elf_path, "wb");
  if (!fp || (elf_size > 0 && fwrite(elf_data, 1, elf_size, fp) != elf_size)) {
    warning("Unable to write ELF file: %s", elf_path);
    status = -1;
    goto done;
  }
  status = 1;

done:
  if (fp) fclose(fp);
  free(elf_data);
  free(self_data);
  return status;
}
