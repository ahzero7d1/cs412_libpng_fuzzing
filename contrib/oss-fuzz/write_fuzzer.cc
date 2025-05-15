#include <stddef.h>
#include <stdint.h>
#include <vector>
#include <string.h>
#include "png.h"

struct Buffer {
  std::vector<uint8_t> data;
};

void write_data(png_structp png_ptr, png_bytep data, png_size_t length) {
  auto* buf = static_cast<Buffer*>(png_get_io_ptr(png_ptr));
  buf->data.insert(buf->data.end(), data, data + length);
}

void flush_data(png_structp) {}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 1) return 0;

  const int width = 8;
  const int height = 8;
  const int bit_depth = 8;
  const int color_type = PNG_COLOR_TYPE_RGB;

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

  Buffer buf;
  png_set_write_fn(png_ptr, &buf, write_data, flush_data);

  png_set_IHDR(png_ptr, info_ptr,
               width, height,
               bit_depth, color_type,
               PNG_INTERLACE_NONE,
               PNG_COMPRESSION_TYPE_BASE,
               PNG_FILTER_TYPE_BASE);

  // Prepare image data: RGB for each pixel
  std::vector<uint8_t> image_data(width * height * 3, 0xFF);
  std::vector<png_bytep> row_ptrs(height);
  for (int y = 0; y < height; ++y)
    row_ptrs[y] = image_data.data() + y * width * 3;

  png_write_png(png_ptr, info_ptr, PNG_TRANSFORM_IDENTITY, row_ptrs.data());

  png_destroy_write_struct(&png_ptr, &info_ptr);
  return 0;
}



















