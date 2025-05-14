#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <time.h>

#define PNG_INTERNAL
#include "png.h"

struct WriteBuffer {
  std::vector<uint8_t> data;
};

struct PngHandler {
  png_structp png_ptr = nullptr;
  png_infop info_ptr = nullptr;
  WriteBuffer* buf = nullptr;

  ~PngHandler() {
    if (png_ptr && info_ptr)
      png_destroy_write_struct(&png_ptr, &info_ptr);
    else if (png_ptr)
      png_destroy_write_struct(&png_ptr, nullptr);
    delete buf;
  }
};

void write_data_fn(png_structp png_ptr, png_bytep data, png_size_t length) {
  WriteBuffer* buf = static_cast<WriteBuffer*>(png_get_io_ptr(png_ptr));
  buf->data.insert(buf->data.end(), data, data + length);
}

void flush_fn(png_structp) {}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 100) return 0;

  uint32_t width = ((data[0] << 8) | data[1]) % 128 + 1;
  uint32_t height = ((data[2] << 8) | data[3]) % 128 + 1;
  int color_type = data[4] % 6;
  int bit_depth = 8; // safest
  int interlace_type = data[5] % 2;

  PngHandler handler;
  handler.buf = new WriteBuffer();

  handler.png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!handler.png_ptr) return 0;

  handler.info_ptr = png_create_info_struct(handler.png_ptr);
  if (!handler.info_ptr) return 0;

  if (setjmp(png_jmpbuf(handler.png_ptr))) {
    return 0; // gracefully exit
  }

  png_set_write_fn(handler.png_ptr, handler.buf, write_data_fn, flush_fn);

  // Required: safe fallback for palette mode
  if (color_type == PNG_COLOR_TYPE_PALETTE) {
    png_color palette[2] = {{255, 0, 0}, {0, 255, 0}};
    png_set_PLTE(handler.png_ptr, handler.info_ptr, palette, 2);
  }

  png_set_IHDR(handler.png_ptr, handler.info_ptr,
               width, height, bit_depth, color_type,
               interlace_type, PNG_COMPRESSION_TYPE_BASE, PNG_FILTER_TYPE_BASE);

  // Set dummy rows
  size_t rowbytes = png_get_rowbytes(handler.png_ptr, handler.info_ptr);
  std::vector<uint8_t> image_data(rowbytes * height, 0xFF);
  std::vector<png_bytep> row_ptrs(height);
  for (size_t i = 0; i < height; ++i)
    row_ptrs[i] = image_data.data() + i * rowbytes;

  png_set_rows(handler.png_ptr, handler.info_ptr, row_ptrs.data());

  png_write_png(handler.png_ptr, handler.info_ptr, PNG_TRANSFORM_IDENTITY, nullptr);

  return 0;
}














