#include <stddef.h>
#include <stdint.h>
#include <vector>
#include <string.h>

#include "png.h"

struct Buffer {
  std::vector<uint8_t> data;
};

void write_data(png_structp png_ptr, png_bytep data, png_size_t length) {
  auto* buffer = static_cast<Buffer*>(png_get_io_ptr(png_ptr));
  buffer->data.insert(buffer->data.end(), data, data + length);
}

void flush_data(png_structp) {}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 4) return 0;

  int width = 32;
  int height = 32;
  int bit_depth = 8;
  int color_type = PNG_COLOR_TYPE_RGB;

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

  Buffer buffer;
  png_set_write_fn(png_ptr, &buffer, write_data, flush_data);

  png_set_IHDR(png_ptr, info_ptr,
               width, height,
               bit_depth, color_type,
               PNG_INTERLACE_NONE,
               PNG_COMPRESSION_TYPE_DEFAULT,
               PNG_FILTER_TYPE_DEFAULT);

  png_write_info(png_ptr, info_ptr);

  std::vector<uint8_t> image_data(width * 3 * height, 0x42);
  std::vector<png_bytep> rows(height);
  for (int i = 0; i < height; ++i) {
    rows[i] = image_data.data() + i * width * 3;
  }

  png_write_image(png_ptr, rows.data());
  png_write_end(png_ptr, nullptr);
  png_destroy_write_struct(&png_ptr, &info_ptr);

  return 0;
}


















