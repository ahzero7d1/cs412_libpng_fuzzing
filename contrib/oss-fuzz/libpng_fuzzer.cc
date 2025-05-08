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

// png_read_write_fuzzer.cc
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

#define PNG_NO_PREFIX
#include "png.h"

// A trivial progressive-read callback suite:
static void prog_info_fn(png_structp png, png_infop info) {}
static void prog_row_fn(png_structp png, png_bytep row, png_uint_32 y, int pass) {}
static void prog_end_fn(png_structp png, png_infop info) {}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const size_t kSigBytes = 8;
  if (size < kSigBytes) return 0;
  // Check PNG signature
  if (png_sig_cmp((png_const_bytep)data, 0, kSigBytes)) return 0;

  // --- Progressive read setup ---
  png_structp read_ptr = png_create_read_struct(
      PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!read_ptr) return 0;
  png_infop read_info = png_create_info_struct(read_ptr);
  if (!read_info) {
    png_destroy_read_struct(&read_ptr, nullptr, nullptr);
    return 0;
  }
  png_infop read_end = png_create_info_struct(read_ptr);
  if (!read_end) {
    png_destroy_read_struct(&read_ptr, &read_info, nullptr);
    return 0;
  }
  if (setjmp(png_jmpbuf(read_ptr))) {
    png_destroy_read_struct(&read_ptr, &read_info, &read_end);
    return 0;
  }

  // Hook up progressive reader
  png_set_progressive_read_fn(read_ptr, nullptr,
                              prog_info_fn, prog_row_fn, prog_end_fn);
  // Feed all the data after the signature
  png_process_data(read_ptr, read_info, (png_bytep)(data + kSigBytes),
                   size - kSigBytes);

  // --- Minimal write path ---
  // Create a write struct
  png_structp write_ptr = png_create_write_struct(
      PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!write_ptr) {
    png_destroy_read_struct(&read_ptr, &read_info, &read_end);
    return 0;
  }
  png_infop write_info = png_create_info_struct(write_ptr);
  if (!write_info) {
    png_destroy_write_struct(&write_ptr, nullptr);
    png_destroy_read_struct(&read_ptr, &read_info, &read_end);
    return 0;
  }
  if (setjmp(png_jmpbuf(write_ptr))) {
    png_destroy_write_struct(&write_ptr, &write_info);
    png_destroy_read_struct(&read_ptr, &read_info, &read_end);
    return 0;
  }

  // Declare a 1×1 gray-scale image
  png_set_IHDR(write_ptr, write_info,
               /*width=*/1, /*height=*/1,
               /*bit_depth=*/8,
               /*color_type=*/PNG_COLOR_TYPE_GRAY,
               /*interlace=*/PNG_INTERLACE_NONE,
               /*compression=*/PNG_COMPRESSION_TYPE_BASE,
               /*filter=*/PNG_FILTER_TYPE_BASE);

  // A tiny in-memory buffer for output
  struct MemBuf { uint8_t *buf; size_t  sz, used; };
  MemBuf mb = { (uint8_t*)malloc(128), 128, 0 };

  // Custom write-fn that appends into our MemBuf
  auto write_data = [](png_structp png, png_bytep data, png_size_t len) {
    MemBuf* m = (MemBuf*)png_get_io_ptr(png);
    if (m->used + len <= m->sz) {
      memcpy(m->buf + m->used, data, len);
    }
    m->used += len;
  };
  png_set_write_fn(write_ptr, &mb, write_data, /*flush=*/nullptr);

  png_write_info(write_ptr, write_info);
  // one empty row of 1 byte
  png_bytep row = (png_bytep)malloc(1);
  png_write_row(write_ptr, row);
  png_write_end(write_ptr, write_info);

  free(row);
  free(mb.buf);
  png_destroy_write_struct(&write_ptr, &write_info);
  png_destroy_read_struct(&read_ptr, &read_info, &read_end);

  return 0;
}
