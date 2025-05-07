// libpng_read_fuzzer.cc
// Copyright 2017-2018 Glenn Randers-Pehrson
// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that may
// be found in the LICENSE file https://cs.chromium.org/chromium/src/LICENSE

// The modifications in 2017 by Glenn Randers-Pehrson include
// 1. addition of a PNG_CLEANUP macro,
// 2. setting the option to ignore ADLER32 checksums,
// 3. adding "#include <string.h>" which is needed on some platforms
//    to provide memcpy().
// 4. adding read_end_info() and creating an end_info structure.
// 5. adding calls to png_set_*() transforms commonly used by browsers.

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

#define PNG_INTERNAL
#define PNG_NO_PREFIX
#include "png.h"

#define PNG_CLEANUP_READ                                                \
  if(png_handler.png_ptr) {                                             \
    if (png_handler.row_ptr)                                            \
      png_free(png_handler.png_ptr, png_handler.row_ptr);               \
    if (png_handler.end_info_ptr)                                       \
      png_destroy_read_struct(&png_handler.png_ptr, &png_handler.info_ptr, &png_handler.end_info_ptr); \
    else if (png_handler.info_ptr)                                      \
      png_destroy_read_struct(&png_handler.png_ptr, &png_handler.info_ptr, nullptr); \
    else                                                               \
      png_destroy_read_struct(&png_handler.png_ptr, nullptr, nullptr);   \
    png_handler.png_ptr = nullptr;                                      \
    png_handler.row_ptr = nullptr;                                      \
    png_handler.info_ptr = nullptr;                                     \
    png_handler.end_info_ptr = nullptr;                                 \
  }

// Memory-write helper for png_write
struct MemState {
  uint8_t*  buffer;
  size_t    capacity;
  size_t    used;
};

void write_mem_fn(png_structp png_ptr, png_bytep data, png_size_t length) {
  MemState* ms = reinterpret_cast<MemState*>(png_get_io_ptr(png_ptr));
  if (ms->used + length > ms->capacity) {
    // grow buffer
    size_t newCap = (ms->capacity + length) * 2;
    ms->buffer = reinterpret_cast<uint8_t*>(realloc(ms->buffer, newCap));
    ms->capacity = newCap;
  }
  memcpy(ms->buffer + ms->used, data, length);
  ms->used += length;
}

void flush_mem_fn(png_structp) {}

// Progressive read callbacks
void prog_info_cb(png_structp png_ptr, png_infop info) {}
void prog_row_cb(png_structp png_ptr, png_bytep new_row, png_uint_32 row_num, int pass) {}
void prog_end_cb(png_structp png_ptr, png_infop info) {}

// Existing read harness structures
struct BufState {
  const uint8_t* data;
  size_t bytes_left;
};

struct PngObjectHandler {
  png_structp png_ptr = nullptr;
  png_infop   info_ptr = nullptr;
  png_infop   end_info_ptr = nullptr;
  void*       row_ptr = nullptr;
  BufState*   buf_state = nullptr;
  ~PngObjectHandler() {
    if (row_ptr)
      png_free(png_ptr, row_ptr);
    if (end_info_ptr)
      png_destroy_read_struct(&png_ptr, &info_ptr, &end_info_ptr);
    else if (info_ptr)
      png_destroy_read_struct(&png_ptr, &info_ptr, nullptr);
    else
      png_destroy_read_struct(&png_ptr, nullptr, nullptr);
    delete buf_state;
  }
};

void user_read_data(png_structp png_ptr, png_bytep data, size_t length) {
  BufState* bs = reinterpret_cast<BufState*>(png_get_io_ptr(png_ptr));
  if (length > bs->bytes_left)
    png_error(png_ptr, "read error");
  memcpy(data, bs->data, length);
  bs->bytes_left -= length;
  bs->data += length;
}

void* limited_malloc(png_structp, png_alloc_size_t size) {
  return (size > 8000000) ? nullptr : malloc(size);
}
void default_free(png_structp, png_voidp ptr) { free(ptr); }

static const int kPngHeaderSize = 8;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < kPngHeaderSize) return 0;
  if (png_sig_cmp(const_cast<png_bytep>(data), 0, kPngHeaderSize)) return 0;

  // pngread
  PngObjectHandler png_handler;
  png_handler.png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!png_handler.png_ptr) return 0;
  png_handler.info_ptr = png_create_info_struct(png_handler.png_ptr);
  if (!png_handler.info_ptr) { PNG_CLEANUP_READ; return 0; }
  png_handler.end_info_ptr = png_create_info_struct(png_handler.png_ptr);
  if (!png_handler.end_info_ptr) { PNG_CLEANUP_READ; return 0; }
  png_set_mem_fn(png_handler.png_ptr, nullptr, limited_malloc, default_free);
  png_set_crc_action(png_handler.png_ptr, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE);
#ifdef PNG_IGNORE_ADLER32
  png_set_option(png_handler.png_ptr, PNG_IGNORE_ADLER32, PNG_OPTION_ON);
#endif
  png_handler.buf_state = new BufState{data + kPngHeaderSize, size - kPngHeaderSize};
  png_set_read_fn(png_handler.png_ptr, png_handler.buf_state, user_read_data);
  png_set_sig_bytes(png_handler.png_ptr, kPngHeaderSize);

  if (setjmp(png_jmpbuf(png_handler.png_ptr))) { PNG_CLEANUP_READ; return 0; }
  png_read_info(png_handler.png_ptr, png_handler.info_ptr);

  if (setjmp(png_jmpbuf(png_handler.png_ptr))) { PNG_CLEANUP_READ; return 0; }
  png_uint_32 width, height;
  int bit_depth, color_type, interlace_type, compression_type;
  int filter_type;
  if (!png_get_IHDR(png_handler.png_ptr, png_handler.info_ptr, &width, &height,
                    &bit_depth, &color_type, &interlace_type,
                    &compression_type, &filter_type)) {
    PNG_CLEANUP_READ; return 0;
  }
  if (width && height > 100000000 / width) { PNG_CLEANUP_READ; return 0; }

  png_set_gray_to_rgb(png_handler.png_ptr);
  png_set_expand(png_handler.png_ptr);
  png_set_packing(png_handler.png_ptr);
  png_set_scale_16(png_handler.png_ptr);
  png_set_tRNS_to_alpha(png_handler.png_ptr);
  int passes = png_set_interlace_handling(png_handler.png_ptr);
  png_read_update_info(png_handler.png_ptr, png_handler.info_ptr);

  png_handler.row_ptr = png_malloc(
     png_handler.png_ptr,
     png_get_rowbytes(png_handler.png_ptr, png_handler.info_ptr)
  );
  for (int pass = 0; pass < passes; ++pass) {
    for (png_uint_32 y = 0; y < height; ++y) {
      png_read_row(png_handler.png_ptr,
                   reinterpret_cast<png_bytep>(png_handler.row_ptr), nullptr);
    }
  }
  png_read_end(png_handler.png_ptr, png_handler.end_info_ptr);

  // pngwrite
  {
    // Initialize write struct
    png_structp wp = png_create_write_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
    if (wp) {
      png_infop wi = png_create_info_struct(wp);
      if (wi) {
        MemState ms{(uint8_t*)malloc(1024), 1024, 0};
        png_set_write_fn(wp, &ms, write_mem_fn, flush_mem_fn);
        // Write header
        png_set_IHDR(wp, wi, width, height, bit_depth, color_type,
                     PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_BASE, PNG_FILTER_TYPE_BASE);
        png_write_info(wp, wi);
        // Write rows
        size_t rowbytes = png_get_rowbytes(wp, wi);
        for (png_uint_32 y = 0; y < height; ++y) {
          png_write_row(wp, reinterpret_cast<png_bytep>(png_handler.row_ptr));
        }
        png_write_end(wp, wi);
        free(ms.buffer);
      }
      png_destroy_write_struct(&wp, nullptr);
    }
  }

  // Progressive read
  {
    png_structp pp = png_create_read_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
    png_infop   pi = pp ? png_create_info_struct(pp) : nullptr;
    if (pp && pi && !setjmp(png_jmpbuf(pp))) {
      png_set_progressive_read_fn(pp, nullptr, prog_info_cb, prog_row_cb, prog_end_cb);
      size_t offset = 0;
      while (offset < size) {
        size_t chunk = rand() % (size - offset) + 1;
        png_process_data(pp, pi, const_cast<png_bytep>(data + offset), chunk);
        offset += chunk;
      }
    }
    if (pp) png_destroy_read_struct(&pp, &pi, nullptr);
  }

  return 0;
}
