// libpng_write_fuzzer.cc
// Copyright 2017-2018 Glenn Randers-Pehrson
// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that may
// be found in the LICENSE file https://cs.chromium.org/chromium/src/LICENSE

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <vector>

#define PNG_INTERNAL
#include "png.h"
#include "writepng.h"

#define PNG_CLEANUP \
  if(png_handler.png_ptr) \
  { \
    if (png_handler.row_ptr) \
      png_free(png_handler.png_ptr, png_handler.row_ptr); \
    if (png_handler.end_info_ptr) \
      png_destroy_write_struct(&png_handler.png_ptr, &png_handler.info_ptr); \
    else if (png_handler.info_ptr) \
      png_destroy_write_struct(&png_handler.png_ptr, &png_handler.info_ptr); \
    else \
      png_destroy_write_struct(&png_handler.png_ptr, nullptr); \
    png_handler.png_ptr = nullptr; \
    png_handler.row_ptr = nullptr; \
    png_handler.info_ptr = nullptr; \
    png_handler.end_info_ptr = nullptr; \
  }

struct WriteBuffer {
  std::vector<uint8_t> data;
};

struct PngObjectHandler {
  png_infop info_ptr = nullptr;
  png_structp png_ptr = nullptr;
  png_infop end_info_ptr = nullptr;
  png_voidp row_ptr = nullptr;
  WriteBuffer* write_buf = nullptr;

  ~PngObjectHandler() {
    if (row_ptr)
      png_free(png_ptr, row_ptr);
    if (info_ptr)
      png_destroy_write_struct(&png_ptr, &info_ptr);
    else
      png_destroy_write_struct(&png_ptr, nullptr);
    delete write_buf;
  }
};

void user_write_data(png_structp png_ptr, png_bytep data, png_size_t length) {
  WriteBuffer* buf = static_cast<WriteBuffer*>(png_get_io_ptr(png_ptr));
  buf->data.insert(buf->data.end(), data, data + length);
}

void user_flush_data(png_structp png_ptr) {
  // Do nothing. Required stub.
}

void* limited_malloc(png_structp png_ptr, png_alloc_size_t size) {
  // libpng may allocate large amounts of memory that the fuzzer reports as
  // an error. In order to silence these errors, make libpng fail when trying
  // to allocate a large amount.
  // This number is chosen to match the default png_user_chunk_malloc_max.
  if (size > 8000000)
    return nullptr;

  return malloc(size);
}

void default_free(png_structp png_ptr, png_voidp ptr) {
  free(ptr);
}

// Entry point for LibFuzzer.
// Roughly follows the libpng book example:
// http://www.libpng.org/pub/png/book/chapter15.html
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 16) {
    return 0; // Not enough data to construct even minimal header.
  }

  // Use some of the input data to define PNG parameters.
  uint32_t width = (data[0] << 8) | data[1];
  uint32_t height = (data[2] << 8) | data[3];
  int bit_depth = (data[4] % 4 + 1) * 8;  // 8, 16, 24, 32
  int color_type = data[5] % 6;          // 0-6 valid color types
  int interlace_type = data[6] % 2;
  int compression_type = PNG_COMPRESSION_TYPE_BASE;
  int filter_type = PNG_FILTER_TYPE_BASE;

  // Limit dimensions to avoid excessive memory usage
  if (width == 0 || height == 0 || width > 4096 || height > 4096)
    return 0;

  PngObjectHandler png_handler;
  png_handler.png_ptr = nullptr;
  png_handler.row_ptr = nullptr;
  png_handler.info_ptr = nullptr;
  png_handler.end_info_ptr = nullptr;


  PNG_CLEANUP
  return 0;
}
