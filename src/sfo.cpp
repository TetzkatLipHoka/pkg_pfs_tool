#include "sfo.hpp"
#include "util.h"
#include <utlist.h>

#ifdef _WIN32
#include <io.h>
#endif

#define SFO_MAGIC "\0PSF"

#define SFO_HEADER_SIZE 0x14
#define SFO_TABLE_ENTRY_SIZE 0x10

TYPE_BEGIN(struct sfo_header, SFO_HEADER_SIZE);
  char magic[4];
  //TYPE_FIELD(char magic[4], 0x00);
  TYPE_FIELD(uint32_t version, 0x04);
  TYPE_FIELD(uint32_t key_table_offset, 0x08);
  TYPE_FIELD(uint32_t value_table_offset, 0x0C);
  TYPE_FIELD(uint32_t entry_count, 0x10);
TYPE_END();
CT_SIZE_ASSERT(struct sfo_header, SFO_HEADER_SIZE);

TYPE_BEGIN(struct sfo_table_entry, SFO_TABLE_ENTRY_SIZE);
  uint16_t key_offset;
  //TYPE_FIELD(uint16_t key_offset, 0x00);
  TYPE_FIELD(uint16_t format, 0x02);
  TYPE_FIELD(uint32_t size, 0x04);
  TYPE_FIELD(uint32_t max_size, 0x08);
  TYPE_FIELD(uint32_t value_offset, 0x0C);
TYPE_END();
CT_SIZE_ASSERT(struct sfo_table_entry, SFO_TABLE_ENTRY_SIZE);

struct sfo* sfo_alloc(void) {
  struct sfo* sfo = NULL;

  sfo = (struct sfo*)malloc(sizeof(*sfo));
  if (!sfo)
    goto error;
  memset(sfo, 0, sizeof(*sfo));

  return sfo;

error:
  if (sfo)
    free(sfo);

  return NULL;
}

void sfo_free(struct sfo* sfo) {
  struct sfo_entry* entry;
  struct sfo_entry* tmp;

  if (!sfo)
    return;

  DL_FOREACH_SAFE(sfo->entries, entry, tmp) {
    DL_DELETE(sfo->entries, entry);

    if (entry->key)
      free(entry->key);

    if (entry->value)
      free(entry->value);

    free(entry);
  }

  free(sfo);
}

int sfo_load_from_file(struct sfo* sfo, const char* file_path) {
  struct stat stats;
  uint8_t* data = NULL;
  size_t data_size;
  ssize_t nread;
  int fd = -1;
  int status = 0;
  int ret;

  assert(sfo != NULL);
  assert(file_path != NULL);

  fd = open(file_path, O_RDONLY | O_BINARY);
  if (fd < 0) {
    warning("Unable to open file.");
    goto error;
  }

  ret = fstat(fd, &stats);
  if (ret < 0) {
    warning("Unable to get file information.");
    goto error;
  }
  data_size = (size_t)stats.st_size;

  data = (uint8_t*)malloc(data_size);
  if (!data) {
    warning("Unable to allocate memory of 0x%" PRIuMAX " bytes.", (uintmax_t)data_size);
    goto error;
  }

  nread = read(fd, data, data_size);
  if (nread < 0) {
    warning("Unable to read file.");
    goto error;
  }
  if ((size_t)nread != data_size) {
    warning("Insufficient data read.");
    goto error;
  }

  if (!sfo_load_from_memory(sfo, data, data_size)) {
    warning("Unable to load system file object.");
    goto error;
  }

  status = 1;

error:
  if (data)
    free(data);

  if (fd > 0)
    close(fd);

  return status;
}

int sfo_load_from_memory(struct sfo* sfo, const void* data, size_t data_size) {
  struct sfo_header* hdr;
  struct sfo_table_entry* entry_table;
  struct sfo_table_entry* entry;
  struct sfo_entry* entries = NULL;
  struct sfo_entry* new_entry = NULL;
  const char* key_table;
  const uint8_t* value_table;
  size_t entry_count, i;
  int status = 0;

  assert(sfo != NULL);
  assert(data != NULL);

  if (data_size < sizeof(*hdr)) {
    warning("Insufficient data.");
    goto error;
  }

  hdr = (struct sfo_header*)data;
  if (memcmp(hdr->magic, SFO_MAGIC, sizeof(hdr->magic)) != 0) {
    warning("Invalid system file object format.");
    goto error;
  }

  entry_table = (struct sfo_table_entry*)((size_t)data + sizeof(*hdr));
  entry_count = LE32(hdr->entry_count);
  if (data_size < sizeof(*hdr) + entry_count * sizeof(*entry_table)) {
    warning("Insufficient data.");
    goto error;
  }

  key_table = (const char*)data + LE32(hdr->key_table_offset);
  value_table = (const uint8_t*)data + LE32(hdr->value_table_offset);

  for (i = 0; i < entry_count; ++i) {
    entry = entry_table + i;

    new_entry = (struct sfo_entry*)malloc(sizeof(*new_entry));
    if (!new_entry) {
      warning("Unable to allocate memory for entry.");
      goto error;
    }
    memset(new_entry, 0, sizeof(*new_entry));

    new_entry->format = (enum sfo_value_format)LE16(entry->format);

    new_entry->size = LE32(entry->size);
    new_entry->area = LE32(entry->max_size);
    if (new_entry->area < new_entry->size) {
      warning("Unexpected entry sizes.");
      goto error;
    }

    new_entry->key = strdup(key_table + LE16(entry->key_offset));
    if (!new_entry->key) {
      warning("Unable to allocate memory for entry key.");
      goto error;
    }

    new_entry->value = (uint8_t*)malloc(new_entry->area);
    if (!new_entry->value) {
      warning("Unable to allocate memory for entry value.");
      goto error;
    }
    memset(new_entry->value, 0, new_entry->area);
    memcpy(new_entry->value, value_table + LE16(entry->value_offset), new_entry->size);

    DL_APPEND(entries, new_entry);
  }
  new_entry = NULL;

  sfo->entries = entries;

  status = 1;

error:
  if (new_entry) {
    if (new_entry->key)
      free(new_entry->key);

    if (new_entry->value)
      free(new_entry->value);

    free(new_entry);
  }

  return status;
}

int sfo_save_to_file(struct sfo* sfo, const char* file_path) {
  struct sfo_entry* entry;
  struct sfo_header hdr;
  uint8_t* buf = NULL;
  FILE* fp = NULL;
  size_t entry_count = 0, key_table_size = 0, value_table_size = 0;
  size_t key_table_offset, value_table_offset, total_size;
  size_t entry_pos, key_pos, value_pos;
  int status = 0;

  assert(sfo != NULL);
  assert(file_path != NULL);

  DL_FOREACH(sfo->entries, entry) {
    ++entry_count;
    key_table_size += strlen(entry->key) + 1;
    value_table_size += entry->area;
  }

  key_table_offset = SFO_HEADER_SIZE + entry_count * SFO_TABLE_ENTRY_SIZE;
  value_table_offset = key_table_offset + key_table_size;
  total_size = value_table_offset + value_table_size;

  buf = (uint8_t*)malloc(total_size ? total_size : 1);
  if (!buf)
    goto error;
  memset(buf, 0, total_size);

  memset(&hdr, 0, sizeof(hdr));
  memcpy(hdr.magic, SFO_MAGIC, sizeof(hdr.magic));
  hdr.version = LE32(0x00000101);
  hdr.key_table_offset = LE32((uint32_t)key_table_offset);
  hdr.value_table_offset = LE32((uint32_t)value_table_offset);
  hdr.entry_count = LE32((uint32_t)entry_count);
  memcpy(buf, &hdr, sizeof(hdr));

  entry_pos = SFO_HEADER_SIZE;
  key_pos = 0;
  value_pos = 0;
  DL_FOREACH(sfo->entries, entry) {
    struct sfo_table_entry te;
    size_t key_len = strlen(entry->key) + 1;

    memset(&te, 0, sizeof(te));
    te.key_offset = LE16((uint16_t)key_pos);
    te.format = LE16((uint16_t)entry->format);
    te.size = LE32((uint32_t)entry->size);
    te.max_size = LE32((uint32_t)entry->area);
    te.value_offset = LE32((uint32_t)value_pos);
    memcpy(buf + entry_pos, &te, sizeof(te));
    entry_pos += SFO_TABLE_ENTRY_SIZE;

    memcpy(buf + key_table_offset + key_pos, entry->key, key_len);
    key_pos += key_len;

    if (entry->value && entry->size > 0)
      memcpy(buf + value_table_offset + value_pos, entry->value, entry->size);
    value_pos += entry->area;
  }

  fp = fopen(file_path, "wb");
  if (!fp) {
    warning("Unable to open '%s' for writing.", file_path);
    goto error;
  }
  if (fwrite(buf, 1, total_size, fp) != total_size) {
    warning("Unable to write system file object.");
    goto error;
  }

  status = 1;

error:
  if (fp)
    fclose(fp);
  if (buf)
    free(buf);
  return status;
}

struct sfo_entry* sfo_find_entry(struct sfo* sfo, const char* key) {
  struct sfo_entry* entry;

  assert(sfo != NULL);
  assert(key != NULL);

  DL_FOREACH(sfo->entries, entry) {
    if (strcmp(entry->key, key) == 0)
      return entry;
  }

  return NULL;
}

void sfo_dump(struct sfo* sfo) {
  struct sfo_entry* entry;
  FILE* fp = stdout;
  size_t index = 0;

  assert(sfo != NULL);

  DL_FOREACH(sfo->entries, entry) {
    fprintf(fp, "%s:\n", entry->key);
    if (entry->value) {
      if (entry->format == SFO_FORMAT_STRING)
        fprintf(fp, "  %s\n", (char*)entry->value);
      else
        fprintf_hex(fp, entry->value, entry->size, 2);
    } else {
      fprintf(fp, "  no value\n");
    }
    ++index;
  }
}

static const char* SFO_KEY_PUBTOOLINFO = "PUBTOOLINFO";
static const char* SFO_KEY_PUBTOOLINFO_SDK_VER = "sdk_ver=";
static const char* SFO_KEY_PUBTOOLINFO_SDK_VER_DEFAULT = "05050000";

int sfo_backport(struct sfo* sfo, const char* SDK_Version) {
  assert(sfo != NULL);
  struct sfo_entry* entry;
  const char* sdk_Version;
  sdk_Version = SDK_Version ? SDK_Version : SFO_KEY_PUBTOOLINFO_SDK_VER_DEFAULT;

  DL_FOREACH(sfo->entries, entry) {
    if (strcmp(entry->key, SFO_KEY_PUBTOOLINFO) == 0) {
      char* val;
      char ccur[9];
      uint64_t cur, new_ver;

      if (!entry->value)
        return -4;
      if (entry->format != SFO_FORMAT_STRING)
        return -3;
      val = strstr((char*)entry->value, SFO_KEY_PUBTOOLINFO_SDK_VER);
      if (!val)
        return -2;
      val += strlen(SFO_KEY_PUBTOOLINFO_SDK_VER);

      memcpy(ccur, val, 8);
      ccur[8] = '\0';
      cur = strtoull(ccur, NULL, 10);
      new_ver = strtoull(sdk_Version, NULL, 10);
      if (new_ver > cur) /* refuse to upgrade */
        return 1;

      memcpy(val, sdk_Version, strlen(sdk_Version));
    } else if (strcmp(entry->key, "SYSTEM_VER") == 0) {
      unsigned int verI[4] = { 0x07, 0x00, 0x05, 0x05 };
      char ver[4];
      size_t i, j;

      if (!entry->value)
        return -1;

      j = strlen(sdk_Version) / 2;
      for (i = 0; i < strlen(sdk_Version) / 2; i++) {
        j--;
        sscanf(sdk_Version + 2 * i, "%02x", &verI[j]);
        ver[j] = (char)verI[j];
      }
      memcpy(entry->value, ver, entry->size);
    }
  }

  return 0;
}