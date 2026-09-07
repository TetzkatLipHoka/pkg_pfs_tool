#pragma once

#include "common.hpp"

#ifdef __cplusplus
extern "C" {
#endif

enum sfo_value_format {
  SFO_FORMAT_STRING_SPECIAL = 0x004,
  SFO_FORMAT_STRING = 0x204,
  SFO_FORMAT_UINT32 = 0x404,
};

struct sfo_entry {
  char* key;
  size_t size;
  size_t area;
  void* value;
  enum sfo_value_format format;
  struct sfo_entry* next;
  struct sfo_entry* prev;
};

struct sfo {
  struct sfo_entry* entries;
};

struct sfo* sfo_alloc(void);
void sfo_free(struct sfo* sfo);

int sfo_load_from_file(struct sfo* sfo, const char* file_path);
int sfo_load_from_memory(struct sfo* sfo, const void* data, size_t data_size);
int sfo_save_to_file(struct sfo* sfo, const char* file_path);

struct sfo_entry* sfo_find_entry(struct sfo* sfo, const char* key);

void sfo_dump(struct sfo* sfo);

/* Downgrade the SFO's SDK/system version (PUBTOOLINFO sdk_ver + SYSTEM_VER) so a
   title is accepted by older firmware. SDK_Version is an 8-char string like
   "05050000"; NULL uses a sane default. */
int sfo_backport(struct sfo* sfo, const char* SDK_Version);

#ifdef __cplusplus
}
#endif