#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <iostream>

#define PNG_INTERNAL
#include "png.h"

struct WriteBuffer {
  std::vector<uint8_t> data;
};

void write_data_fn(png_structp png_ptr, png_bytep data, png_size_t length) {
  WriteBuffer* buf = static_cast<WriteBuffer*>(png_get_io_ptr(png_ptr));
  buf->data.insert(buf->data.end(), data, data + length);
}

void flush_fn(png_structp) {}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 20) return 0;

  uint32_t width = ((data[0] << 8) | data[1]) % 128 + 1;
  uint32_t height = ((data[2] << 8) | data[3]) % 128 + 1;
  int color_type = PNG_COLOR_TYPE_RGB;  // SAFE
  int bit_depth = 8;
  int interlace_type = 0;

  png_structp png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!png_ptr) return 0;

  png_infop info_ptr = png_create_info_struct(png_ptr);
  if (!info_ptr) {
    png_destroy_write_struct(&png_ptr, nullptr);
    return 0;
  }

  if (setjmp(png_jmpbuf(png_ptr))) {
    png_destroy_write_struct(&png_ptr, &info_ptr);
    return 0;
  }

  WriteBuffer buf;
  png_set_write_fn(png_ptr, &buf, write_data_fn, flush_fn);

  png_set_IHDR(png_ptr, info_ptr, width, height, bit_depth, color_type,
               interlace_type, PNG_COMPRESSION_TYPE_BASE, PNG_FILTER_TYPE_BASE);

  // Set dummy rows
  size_t rowbytes = png_get_rowbytes(png_ptr, info_ptr);
  std::vector<uint8_t> img_data(rowbytes * height, 0xFF);
  std::vector<png_bytep> row_pointers(height);
  for (size_t i = 0; i < height; ++i)
    row_pointers[i] = img_data.data() + i * rowbytes;

  png_set_rows(png_ptr, info_ptr, row_pointers.data());

  // NOW SAFE: Single call that does info + rows + end
  png_write_png(png_ptr, info_ptr, PNG_TRANSFORM_IDENTITY, nullptr);

  png_destroy_write_struct(&png_ptr, &info_ptr);
  return 0;
}















