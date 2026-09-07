/*
 * PS4 ELF SDK downgrader — stages 1-3 of flatz's Downgrade_ELF2.py.
 * Operates on a decrypted plaintext ELF in place. See elfdowngrade.hpp.
 * Built on the ELF parsing in self.hpp (struct elf / elf64_*).
 */

#include "elfdowngrade.hpp"
#include "self.hpp"
#include "util.h"

#include <Zydis.h>

/* Unaligned little-endian helpers (segment fields aren't guaranteed aligned). */
static uint32_t rd32(const uint8_t* p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void wr32(uint8_t* p, uint32_t v) {
  p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static uint32_t rd32be(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static void wr32be(uint8_t* p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}
static uint64_t rd64(const uint8_t* p) {
  return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}
static void wr64(uint8_t* p, uint64_t v) {
  wr32(p, (uint32_t)v); wr32(p + 4, (uint32_t)(v >> 32));
}
/* Write the low nbytes of v little-endian (Zydis disp/imm fields are 1/2/4/8 bytes). */
static void wr_le(uint8_t* p, uint64_t v, unsigned nbytes) {
  unsigned i;
  for (i = 0; i < nbytes; ++i) p[i] = (uint8_t)(v >> (8 * i));
}

/* Program-header field accessors (phdrs live in the LE buffer). */
static uint32_t ph_type(struct elf64_phdr* p)  { return LE32(p->p_type); }
static uint32_t ph_flags(struct elf64_phdr* p) { return LE32(p->p_flags); }
static uint64_t ph_vaddr(struct elf64_phdr* p) { return LE64(p->p_vaddr); }
static uint64_t ph_paddr(struct elf64_phdr* p) { return LE64(p->p_paddr); }
static uint64_t ph_fsz(struct elf64_phdr* p)   { return LE64(p->p_filesz); }
static uint64_t ph_msz(struct elf64_phdr* p)   { return LE64(p->p_memsz); }
static uint64_t ph_off(struct elf64_phdr* p)   { return LE64(p->p_offset); }
static void ph_set_vaddr(struct elf64_phdr* p, uint64_t v) { p->p_vaddr = LE64(v); }
static void ph_set_paddr(struct elf64_phdr* p, uint64_t v) { p->p_paddr = LE64(v); }
static void ph_set_msz(struct elf64_phdr* p, uint64_t v)   { p->p_memsz = LE64(v); }

#define DT_SCE_JMPREL   U64C(0x61000029)
#define DT_SCE_PLTRELSZ U64C(0x6100002D)
#define DT_SCE_RELASZ   U64C(0x61000031)
#define DT_SCE_SYMTAB   U64C(0x61000039)
#define DT_SCE_SYMTABSZ U64C(0x6100003F)
#define MEMHOLE_ALIGN   U64C(0x4000)

static uint64_t align_up64(uint64_t x, uint64_t a) {
  return (x + (a - 1)) & ~(a - 1);
}

static int memhole_cmp(const void* a, const void* b) {
  struct elf64_phdr* pa = *(struct elf64_phdr* const*)a;
  struct elf64_phdr* pb = *(struct elf64_phdr* const*)b;
  uint64_t va = ph_vaddr(pa), vb = ph_vaddr(pb);
  if (va < vb) return -1;
  if (va > vb) return 1;
  /* secondary key: larger (vaddr + mem_size) first (Python -(vaddr+mem_size)). */
  {
    uint64_t ea = va + ph_msz(pa), eb = vb + ph_msz(pb);
    if (ea > eb) return -1;
    if (ea < eb) return 1;
  }
  return 0;
}

/*
 * Pass 1 (segments_fixer.py, code operands): fix instruction disp/imm fields in the
 * before-hole executable code that reference an address inside the moved range. Linear-sweep
 * decode each RX segment up to the hole; for a memory operand that is RIP-relative or a plain
 * absolute address, or an absolute immediate (e.g. `movabs reg, <data ptr>`), whose resolved
 * target is in [vaddr_start, vaddr_end], subtract vaddr_diff from the encoded field. Returns 1
 * if anything changed.
 *
 * ponytail: linear sweep (no IDA-grade code discovery available) + the strict hole-range check
 * is the false-positive guard — the same known ceiling as the reference IDA plugin. A random
 * in-range disp/imm constant that isn't an address gets mis-patched; the moved range is small
 * so collisions are unlikely, but it's the only guard. Only forward refs *into* the moved
 * segment are fixed; backward refs *from* moved executable code are not (design limit — coherent
 * only when the moved segment is non-executable data, which Pass 2 then covers).
 */
static int patch_code_operands(struct elf* elf, const ZydisDecoder* dec,
                               struct elf64_phdr** rx, size_t rx_count,
                               uint64_t vaddr_start, uint64_t vaddr_end, uint64_t vaddr_diff) {
  size_t s;
  int changed = 0;
  for (s = 0; s < rx_count; ++s) {
    uint64_t base_off = ph_off(rx[s]);
    uint64_t base_va  = ph_vaddr(rx[s]);
    uint64_t flen     = ph_fsz(rx[s]);
    uint64_t o = 0;
    if (base_va >= vaddr_start) continue;   /* whole segment lies past the hole */
    if (base_off >= elf->size) continue;
    if (base_off + flen > elf->size) flen = elf->size - base_off;
    while (o < flen) {
      uint64_t ip = base_va + o;
      ZydisDecodedInstruction ins;
      ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
      uint64_t avail;
      unsigned k;
      if (ip >= vaddr_start) break;          /* before-hole region only */
      avail = elf->size - (base_off + o);
      if (avail > 15) avail = 15;            /* max x86-64 instruction length */
      if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(dec, elf->data + base_off + o, avail, &ins, ops))) {
        o += 1;                              /* resync on the next byte */
        continue;
      }
      /* Memory-operand displacement: RIP-relative or plain-absolute. */
      for (k = 0; k < ins.operand_count_visible; ++k) {
        ZydisDecodedOperand* op = &ops[k];
        uint64_t target;
        if (op->type != ZYDIS_OPERAND_TYPE_MEMORY || ins.raw.disp.size == 0)
          continue;
        if (op->mem.base == ZYDIS_REGISTER_RIP) {
          if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins, op, ip, &target)))
            continue;
        } else if (op->mem.base == ZYDIS_REGISTER_NONE && op->mem.index == ZYDIS_REGISTER_NONE) {
          target = (uint64_t)ins.raw.disp.value;  /* [disp] absolute */
        } else {
          continue;                          /* base/index register-relative: not a fixed VA */
        }
        if (target >= vaddr_start && target <= vaddr_end) {
          wr_le(elf->data + base_off + o + ins.raw.disp.offset,
                (uint64_t)ins.raw.disp.value - vaddr_diff, ins.raw.disp.size / 8);
          changed = 1;
        }
      }
      /* Absolute immediate holding a moved-range address (missed by the IDA plugin). */
      for (k = 0; k < 2; ++k) {
        uint64_t v;
        if (ins.raw.imm[k].size == 0 || ins.raw.imm[k].is_relative)
          continue;
        v = ins.raw.imm[k].value.u;
        if (v >= vaddr_start && v <= vaddr_end) {
          wr_le(elf->data + base_off + o + ins.raw.imm[k].offset, v - vaddr_diff,
                ins.raw.imm[k].size / 8);
          changed = 1;
        }
      }
      o += ins.length ? ins.length : 1;
    }
  }
  return changed;
}

/*
 * Stage 4: memory-hole removal (Downgrade_ELF2.py --patch-memhole 2). Compacts
 * writable LOAD/RELRO segments so there are no gaps (old kernels reject
 * non-contiguous RELRO/DATA), then rewrites the dynamic / relocation / symbol
 * table virtual addresses that fall past each hole. Only runs for a target fw
 * < 6.00. Operates on elf->data in place. Returns 1 if anything changed.
 */
static int patch_memhole(struct elf* elf) {
  size_t phnum = LE16(elf->ehdr->e_phnum);
  struct elf64_phdr** segs = NULL;
  struct elf64_phdr** rx_segs = NULL;
  size_t nseg = 0, rx_count = 0;
  struct elf64_phdr* dynamic_ph = NULL;
  struct elf64_phdr* dynlib_ph = NULL;
  uint64_t dyn_addr = 0, rela_addr = 0, sym_addr = 0, rela_size = 0, sym_size = 0;
  uint64_t dyn_count = 0, rela_count = 0, sym_count = 0;
  size_t i, j, a;
  int changed = 0;
  ZydisDecoder decoder;
  int have_decoder = ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64));

  segs = (struct elf64_phdr**)malloc((phnum ? phnum : 1) * sizeof(*segs));
  rx_segs = (struct elf64_phdr**)malloc((phnum ? phnum : 1) * sizeof(*rx_segs));
  if (!segs || !rx_segs) {
    free(segs); free(rx_segs);
    return 0;
  }

  /* Collect RX (executable) LOAD segments — Pass 1 sweeps these for cross-hole operands. */
  for (i = 0; i < phnum; ++i) {
    struct elf64_phdr* p = &elf->phdrs[i];
    if (ph_type(p) == ELF_PT_LOAD && ph_flags(p) == ELF_PF_READ_EXEC)
      rx_segs[rx_count++] = p;
  }

  /* Pass 1: writable LOAD + RELRO (skip the RX text segment). */
  for (i = 0; i < phnum; ++i) {
    struct elf64_phdr* p = &elf->phdrs[i];
    uint32_t t = ph_type(p);
    if (t != ELF_PT_LOAD && t != ELF_PT_SCE_RELRO)
      continue;
    if (t == ELF_PT_LOAD && ph_flags(p) == ELF_PF_READ_EXEC)
      continue;
    segs[nseg++] = p;
  }
  /* Pass 2: pull in any phdr sharing a collected segment's paddr or vaddr. */
  for (i = 0; i < phnum; ++i) {
    struct elf64_phdr* p = &elf->phdrs[i];
    int in = 0, match = 0;
    for (j = 0; j < nseg; ++j) if (segs[j] == p) { in = 1; break; }
    if (in) continue;
    for (j = 0; j < nseg; ++j) if (ph_paddr(segs[j]) == ph_paddr(p)) { match = 1; break; }
    if (!match) for (j = 0; j < nseg; ++j) if (ph_vaddr(segs[j]) == ph_vaddr(p)) { match = 1; break; }
    if (match) segs[nseg++] = p;
  }

  if (nseg > 1)
    qsort(segs, nseg, sizeof(*segs), &memhole_cmp);

  /* Drop segments fully nested in their predecessor (same type). */
  i = 1;
  while (i < nseg) {
    struct elf64_phdr* s = segs[i];
    struct elf64_phdr* pv = segs[i - 1];
    if (ph_vaddr(s) >= ph_vaddr(pv) &&
        ph_vaddr(s) + ph_msz(s) <= ph_vaddr(pv) + ph_msz(pv) &&
        ph_type(s) == ph_type(pv)) {
      for (j = i; j + 1 < nseg; ++j) segs[j] = segs[j + 1];
      --nseg;
    } else {
      ++i;
    }
  }

  /* Locate dynamic + dynlibdata, then scan dynamic tags for table offsets/sizes. */
  for (i = 0; i < phnum; ++i) {
    struct elf64_phdr* p = &elf->phdrs[i];
    if (ph_type(p) == ELF_PT_DYNAMIC) dynamic_ph = p;
    else if (ph_type(p) == ELF_PT_SCE_DYNLIBDATA) dynlib_ph = p;
  }
  if (!dynamic_ph || !dynlib_ph) {
    warning("Memhole: not a valid OELF (no dynamic/dynlibdata); skipping.");
    free(segs); free(rx_segs);
    return 0;
  }
  dyn_addr = ph_off(dynamic_ph);
  dyn_count = ph_msz(dynamic_ph) / 16;
  rela_addr = ph_off(dynlib_ph);
  sym_addr = ph_off(dynlib_ph);
  for (i = 0; i < dyn_count; ++i) {
    uint64_t off = dyn_addr + i * 16;
    uint64_t tag, val;
    if (off + 16 > elf->size) break;
    tag = rd64(elf->data + off);
    val = rd64(elf->data + off + 8);
    if (tag == DT_SCE_JMPREL) rela_addr += val;
    else if (tag == DT_SCE_PLTRELSZ) rela_size += val;
    else if (tag == DT_SCE_RELASZ) rela_size += val;
    else if (tag == DT_SCE_SYMTAB) sym_addr += val;
    else if (tag == DT_SCE_SYMTABSZ) sym_size += val;
  }
  rela_count = rela_size / 24; /* struct.calcsize('<QLLq') */
  sym_count = sym_size / 24;   /* struct.calcsize('<IBBHQQ') */

  /* Walk adjacent segment pairs; compact each hole and fix table addresses. */
  for (a = 0; a + 1 < nseg; ++a) {
    struct elf64_phdr* seg = segs[a];
    struct elf64_phdr* next = segs[a + 1];
    uint64_t mem_size_aligned = align_up64(ph_msz(seg), MEMHOLE_ALIGN);
    uint64_t old_vaddr, new_vaddr, new_paddr, new_mem_size;
    uint64_t vaddr_start, vaddr_mem_size, vaddr_end, vaddr_diff;

    if (ph_vaddr(seg) + mem_size_aligned >= ph_vaddr(next))
      continue; /* no hole here */

    {
      /* Capture next's old addresses/sizes BEFORE moving it. */
      uint64_t old_paddr = ph_paddr(next);
      uint64_t paddr_mem_size = ph_msz(next);
      uint64_t paddr_file_size = ph_fsz(next);
      uint64_t vaddr_file_size = ph_fsz(next);
      old_vaddr = ph_vaddr(next);
      vaddr_start = old_vaddr;
      vaddr_mem_size = ph_msz(next);

      new_mem_size = mem_size_aligned;
      new_paddr = ph_paddr(seg) + new_mem_size;
      new_vaddr = ph_vaddr(seg) + new_mem_size;

      ph_set_msz(seg, new_mem_size);
      ph_set_paddr(next, new_paddr);
      ph_set_vaddr(next, new_vaddr);

      /* Propagate the move to later segments that shared next's old addresses;
         widen vaddr_mem_size to the largest propagated mem_size. Stops at the
         first segment that matches nothing. ponytail: faithful port of flatz'
         quirks — a vaddr match assigns next's *paddr* (not vaddr), and the
         file_size comparisons fold mem_size into their accumulators; kept as
         shipped (only vaddr_mem_size feeds the patch range; the paddr/file_size
         accumulators exist only to reproduce the loop's stop condition). */
      for (j = a + 2; j < nseg; ++j) {
        int hit = 0;
        if (ph_paddr(segs[j]) == old_paddr) { ph_set_paddr(segs[j], new_paddr); hit = 1; }
        if (ph_vaddr(segs[j]) == old_vaddr) { ph_set_vaddr(segs[j], new_paddr); hit = 1; }
        if (ph_msz(segs[j]) > paddr_mem_size) { paddr_mem_size = ph_msz(segs[j]); hit = 1; }
        if (ph_msz(segs[j]) > vaddr_mem_size) { vaddr_mem_size = ph_msz(segs[j]); hit = 1; }
        if (ph_fsz(segs[j]) > paddr_file_size) { paddr_file_size = ph_msz(segs[j]); hit = 1; }
        if (ph_fsz(segs[j]) > vaddr_file_size) { vaddr_file_size = ph_msz(segs[j]); hit = 1; }
        if (!hit) break;
      }
      (void)paddr_mem_size; (void)paddr_file_size; (void)vaddr_file_size;
    }

    vaddr_end = vaddr_start + vaddr_mem_size - 1;
    vaddr_diff = old_vaddr - new_vaddr;

    /* Patch dynamic table (skip the four table-locating tags). */
    for (i = 0; i < dyn_count; ++i) {
      uint64_t off = dyn_addr + i * 16;
      uint64_t tag, val;
      if (off + 16 > elf->size) break;
      tag = rd64(elf->data + off);
      val = rd64(elf->data + off + 8);
      if (tag == DT_SCE_JMPREL || tag == DT_SCE_PLTRELSZ || tag == DT_SCE_RELASZ || tag == DT_SCE_SYMTAB)
        continue;
      if (val >= vaddr_start && val <= vaddr_end) {
        wr64(elf->data + off + 8, val - vaddr_diff);
        changed = 1;
      }
    }
    /* Patch relocations: r_offset(0x00) and r_addend(0x10). */
    for (i = 0; i < rela_count; ++i) {
      uint64_t off = rela_addr + i * 24;
      uint64_t r_off, r_add;
      if (off + 24 > elf->size) break;
      r_off = rd64(elf->data + off);
      r_add = rd64(elf->data + off + 16);
      if (r_off >= vaddr_start && r_off <= vaddr_end) { wr64(elf->data + off, r_off - vaddr_diff); changed = 1; }
      if (r_add >= vaddr_start && r_add <= vaddr_end) { wr64(elf->data + off + 16, r_add - vaddr_diff); changed = 1; }
    }
    /* Patch symbols: st_value at +0x08. */
    for (i = 0; i < sym_count; ++i) {
      uint64_t off = sym_addr + i * 24;
      uint64_t stv;
      if (off + 24 > elf->size) break;
      stv = rd64(elf->data + off + 8);
      if (stv >= vaddr_start && stv <= vaddr_end) { wr64(elf->data + off + 8, stv - vaddr_diff); changed = 1; }
    }

    /* Pass 2 (segments_fixer): fix raw 8-byte absolute data pointers into the
       moved range that no relocation covers (vtables, jump/init arrays). Scan
       the before-hole and moved segments' file bytes; a qword in
       [vaddr_start, vaddr_end] is shifted down by vaddr_diff. ponytail: this is
       a heuristic — an 8-aligned non-pointer qword that happens to land in-range
       gets mis-patched; same risk as the reference, guarded only by 8-byte
       alignment + the range check. (Code-operand fixup = Pass 1, TODO: Zydis.) */
    {
      struct elf64_phdr* scan[2];
      int si;
      scan[0] = seg;
      scan[1] = next;
      for (si = 0; si < 2; ++si) {
        uint64_t base = ph_off(scan[si]);
        uint64_t flen = ph_fsz(scan[si]);
        uint64_t o;
        if (base >= elf->size) continue;
        if (base + flen > elf->size) flen = elf->size - base;
        for (o = 0; o + 8 <= flen; o += 8) {
          uint64_t q = rd64(elf->data + base + o);
          if (q >= vaddr_start && q <= vaddr_end) {
            wr64(elf->data + base + o, q - vaddr_diff);
            changed = 1;
          }
        }
      }
    }

    /* Pass 1 (segments_fixer): fix code operands in the before-hole RX segments that
       reference the moved range (RIP-relative / absolute disp, absolute immediate). */
    if (have_decoder &&
        patch_code_operands(elf, &decoder, rx_segs, rx_count, vaddr_start, vaddr_end, vaddr_diff))
      changed = 1;

    info("Memhole compacted at vaddr 0x%" PRIX64 " (shift 0x%" PRIX64 ").", old_vaddr, vaddr_diff);
    changed = 1;
  }

  free(segs); free(rx_segs);
  return changed;
}

static struct elf64_phdr* elf_find_phdr(struct elf* elf, uint32_t type) {
  size_t n = LE16(elf->ehdr->e_phnum), i;
  for (i = 0; i < n; ++i) {
    if (LE32(elf->phdrs[i].p_type) == type)
      return &elf->phdrs[i];
  }
  return NULL;
}

/* Stage 1: proc/module param structure sdk_version at seg+0x10. */
static int patch_param_sdk(struct elf* elf, uint16_t etype, uint32_t new_sdk) {
  uint32_t needed_type;
  const uint8_t* magic;
  struct elf64_phdr* ph;
  uint8_t* seg;
  uint64_t off, fsz;
  uint32_t param_size, old_sdk;
  static const uint8_t proc_magic[4] = { 'O', 'R', 'B', 'I' };
  static const uint8_t mod_magic[4]  = { 0xBF, 0xF4, 0x13, 0x3C };

  if (etype == ELF_ET_SCE_EXEC || etype == ELF_ET_SCE_EXEC_ASLR) {
    needed_type = ELF_PT_SCE_PROCPARAM;
    magic = proc_magic;
  } else {
    needed_type = ELF_PT_SCE_MODULE_PARAM;
    magic = mod_magic;
  }

  ph = elf_find_phdr(elf, needed_type);
  if (!ph)
    return 0; /* param segment absent (e.g. old-sdk elf) */

  off = LE64(ph->p_offset);
  fsz = LE64(ph->p_filesz);
  if (off + fsz > elf->size || fsz < 0x14)
    return 0;
  seg = elf->data + off;

  param_size = rd32(seg);
  if (param_size < 0x14 || param_size > fsz)
    return -1;
  if (memcmp(seg + 0x8, magic, 4) != 0) {
    warning("Unexpected param structure magic; skipping param sdk patch.");
    return -1;
  }

  old_sdk = rd32(seg + 0x10);
  if (old_sdk > new_sdk) {
    wr32(seg + 0x10, new_sdk);
    return 1;
  }
  return 0;
}

/* Stage 2: PT_SCE_VERSION library list, each entry "name:<BE32 sdk>". */
static int patch_version_segment(struct elf* elf, uint32_t new_sdk) {
  struct elf64_phdr* ph;
  uint8_t* seg;
  uint64_t off, fsz, o;
  int nonzero = 0, changed = 0;

  if (new_sdk == 0)
    return 0;
  ph = elf_find_phdr(elf, ELF_PT_SCE_VERSION);
  if (!ph)
    return 0;

  off = LE64(ph->p_offset);
  fsz = LE64(ph->p_filesz);
  if (off + fsz > elf->size)
    return -1;
  seg = elf->data + off;

  for (o = 0; o < fsz; ++o) {
    if (seg[o] != 0) { nonzero = 1; break; }
  }
  if (!nonzero)
    return 0; /* selfutil: version segment is zeroed, cannot patch */

  o = 0;
  while (o < fsz) {
    uint8_t length = seg[o];
    uint8_t* entry;
    uint8_t* colon;
    uint8_t* ver;
    ++o;
    if (o + length > fsz)
      break;
    entry = seg + o;
    /* Python splits on the first ':', requiring the remainder to be 4 bytes. */
    colon = (uint8_t*)memchr(entry, ':', length);
    if (colon && (size_t)((entry + length) - (colon + 1)) == 4) {
      ver = colon + 1;
      if (rd32be(ver) > new_sdk) {
        wr32be(ver, new_sdk);
        changed = 1;
      }
    }
    o += length;
  }
  return changed ? 1 : 0;
}

static uint8_t* read_file(const char* path, size_t* out_size) {
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

int elf_downgrade_file(const char* path, uint32_t target_sdk) {
  uint8_t* buf = NULL;
  size_t size = 0;
  struct elf* elf = NULL;
  uint16_t etype;
  FILE* fp = NULL;
  int r, status = 0;

  buf = read_file(path, &size);
  if (!buf)
    return -1;

  /* is_inner=1 so elf_alloc skips the ex_info probe at 0x3F00 (would OOB on small elfs). */
  elf = elf_alloc(buf, size, 1);
  if (!elf) {
    free(buf);
    return -1;
  }

  etype = LE16(elf->ehdr->e_type);
  if (etype != ELF_ET_SCE_EXEC && etype != ELF_ET_SCE_EXEC_ASLR && etype != ELF_ET_SCE_DYNAMIC) {
    /* Not an SCE executable/module — nothing to downgrade. */
    goto done;
  }

  if (target_sdk != 0) {
    r = patch_param_sdk(elf, etype, target_sdk);
    if (r < 0) { status = -1; goto done; }
    r = patch_version_segment(elf, target_sdk);
    if (r < 0) { status = -1; goto done; }
  }

  /* Stage 4: memory-hole removal — only meaningful for a target firmware < 6.00
     (matches Downgrade_ELF2.py --patch-memhole 2). Requires an explicit sub-6.00
     --sdk-version so it never fires unintentionally. */
  if (target_sdk != 0 && target_sdk < U32C(0x06000000))
    patch_memhole(elf);

  /* Stage 3: zero section-header offset/count (orbis-bin compatibility). */
  elf->ehdr->e_shoff = LE64(0);
  elf->ehdr->e_shnum = LE16(0);

  /* Write the patched buffer back in place. */
  fp = fopen(path, "wb");
  if (!fp || (size > 0 && fwrite(buf, 1, size, fp) != size)) {
    warning("Unable to write downgraded ELF: %s", path);
    status = -1;
    goto done;
  }
  status = 1;

done:
  if (fp) fclose(fp);
  if (elf) elf_free(elf);
  if (buf) free(buf);
  return status;
}
