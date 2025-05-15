#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

#define PNG_INTERNAL
#include "png.h"

struct WriteBuffer {
  std::vector<uint8_t> data;
};

static void user_write_data(png_structp png_ptr, png_bytep data, png_size_t length) {
  auto* buf = static_cast<WriteBuffer*>(png_get_io_ptr(png_ptr));
  buf->data.insert(buf->data.end(), data, data + length);
}

static void user_flush_data(png_structp) {}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 12) return 0;

  int width = (data[0] << 8) | data[1];
  int height = (data[2] << 8) | data[3];
  if (width == 0 || height == 0 || width > 1000 || height > 1000) return 0;

  int bit_depth = 8;
  int color_type = data[4] % 6;
  int interlace = data[5] % 2;
  int compression = PNG_COMPRESSION_TYPE_BASE;
  int filter = PNG_FILTER_TYPE_BASE;

  WriteBuffer write_buf;
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

  png_set_write_fn(png_ptr, &write_buf, user_write_data, user_flush_data);

  png_set_IHDR(png_ptr, info_ptr, width, height, bit_depth, color_type,
               interlace, compression, filter);

  // Optional: set dummy PLTE if palette
  if (color_type == PNG_COLOR_TYPE_PALETTE) {
    png_color palette[2] = {{255, 0, 0}, {0, 255, 0}};
    png_set_PLTE(png_ptr, info_ptr, palette, 2);
  }

  // Allocate row data
  size_t rowbytes = png_get_rowbytes(png_ptr, info_ptr);
  std::vector<uint8_t> image_data(rowbytes * height, 0x80);
  std::vector<png_bytep> row_ptrs(height);
  for (int i = 0; i < height; ++i)
    row_ptrs[i] = image_data.data() + i * rowbytes;

  png_write_png(png_ptr, info_ptr, PNG_TRANSFORM_IDENTITY, nullptr);

  png_destroy_write_struct(&png_ptr, &info_ptr);
  return 0;
}




















