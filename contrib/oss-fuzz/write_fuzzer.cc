// write_fuzzer.cc
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

#include "png.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 16) return 0;

  uint32_t width = (data[0] << 8) | data[1];
  uint32_t height = (data[2] << 8) | data[3];
  if (width == 0 || height == 0 || width > 512 || height > 512) return 0;

  int color_type = data[4] % 6;
  int interlace_type = data[5] % 2;
  int bit_depth_options[] = {1, 2, 4, 8};
  int bit_depth = bit_depth_options[data[6] % 4];

  png_structp png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!png_ptr) return 0;

  png_infop info_ptr = png_create_info_struct(png_ptr);
  if (!info_ptr) {
    png_destroy_write_struct(&png_ptr, nullptr);
    return 0;
  }

  std::vector<uint8_t> out_buf;
  auto write_data = [](png_structp png_ptr, png_bytep data, png_size_t length) {
    auto* buf = static_cast<std::vector<uint8_t>*>(png_get_io_ptr(png_ptr));
    buf->insert(buf->end(), data, data + length);
  };
  auto flush_data = [](png_structp) {};

  if (setjmp(png_jmpbuf(png_ptr))) {
    png_destroy_write_struct(&png_ptr, &info_ptr);
    return 0;
  }

  png_set_write_fn(png_ptr, &out_buf, write_data, flush_data);

  png_set_IHDR(png_ptr, info_ptr, width, height, bit_depth, color_type,
               interlace_type, PNG_COMPRESSION_TYPE_BASE, PNG_FILTER_TYPE_BASE);

  png_set_filter(png_ptr, PNG_FILTER_TYPE_BASE, PNG_ALL_FILTERS);
  png_set_compression_level(png_ptr, 6);

  // Allocate dummy image data
  size_t rowbytes = png_get_rowbytes(png_ptr, info_ptr);
  std::vector<uint8_t> image_data(rowbytes * height, 0);
  std::vector<png_bytep> row_pointers(height);
  for (size_t i = 0; i < height; ++i)
    row_pointers[i] = &image_data[i * rowbytes];

  png_set_rows(png_ptr, info_ptr, row_pointers.data());

  // Write the PNG in one go
  png_write_png(png_ptr, info_ptr, PNG_TRANSFORM_IDENTITY, nullptr);

  png_destroy_write_struct(&png_ptr, &info_ptr);
  return 0;
}
















