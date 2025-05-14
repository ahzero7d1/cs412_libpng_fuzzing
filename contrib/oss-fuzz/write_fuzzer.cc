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

struct PngObjectHandler {
  png_structp png_ptr = nullptr;
  png_infop info_ptr = nullptr;
  WriteBuffer* write_buf = nullptr;

  ~PngObjectHandler() {
    if (png_ptr && info_ptr)
      png_destroy_write_struct(&png_ptr, &info_ptr);
    else if (png_ptr)
      png_destroy_write_struct(&png_ptr, nullptr);
    delete write_buf;
  }
};

void user_write_data(png_structp png_ptr, png_bytep data, png_size_t length) {
  WriteBuffer* buf = static_cast<WriteBuffer*>(png_get_io_ptr(png_ptr));
  buf->data.insert(buf->data.end(), data, data + length);
}

void user_flush_data(png_structp) {
  // Required stub, does nothing
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 100) return 0;

  uint32_t width = (data[0] << 8) | data[1];
  uint32_t height = (data[2] << 8) | data[3];
  if (width == 0 || height == 0 || width > 512 || height > 512) return 0;

  int color_type = data[4] % 6;
  int bit_depths[] = {1, 2, 4, 8};
  int bit_depth = bit_depths[data[5] % 4];
  int interlace_type = data[6] % 2;
  int compression_level = data[7] % 10;
  int filter_method = data[8] % 2;

  PngObjectHandler handler;
  handler.write_buf = new WriteBuffer();

  handler.png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!handler.png_ptr) return 0;

  handler.info_ptr = png_create_info_struct(handler.png_ptr);
  if (!handler.info_ptr) return 0;

  if (setjmp(png_jmpbuf(handler.png_ptr))) return 0;

  png_set_write_fn(handler.png_ptr, handler.write_buf, user_write_data, user_flush_data);
  png_set_IHDR(handler.png_ptr, handler.info_ptr, width, height, bit_depth, color_type,
               interlace_type, PNG_COMPRESSION_TYPE_BASE, filter_method);

  png_set_compression_level(handler.png_ptr, compression_level);
  png_set_filter(handler.png_ptr, PNG_FILTER_TYPE_BASE, PNG_ALL_FILTERS);

  // Add optional chunks
  if (color_type == PNG_COLOR_TYPE_PALETTE) {
    png_color palette[2] = {{255, 0, 0}, {0, 255, 0}};
    png_set_PLTE(handler.png_ptr, handler.info_ptr, palette, 2);
  }

  png_text text_ptr[1];
  text_ptr[0].compression = PNG_TEXT_COMPRESSION_NONE;
  text_ptr[0].key = (char *)"FuzzText";
  text_ptr[0].text = (char *)"Fuzzing metadata";
  png_set_text(handler.png_ptr, handler.info_ptr, text_ptr, 1);

  png_time time_struct = {2025, 5, 13, 12, 0, 0};
  png_set_tIME(handler.png_ptr, handler.info_ptr, &time_struct);

#ifdef PNG_WRITE_UNKNOWN_CHUNKS_SUPPORTED
  png_unknown_chunk unk;
  memcpy(unk.name, "fZzz", 4);
  unk.data = const_cast<png_byte*>(&data[10]);
  unk.size = std::min<size_t>(size - 10, 8);
  unk.location = PNG_HAVE_IHDR;
  png_set_unknown_chunks(handler.png_ptr, handler.info_ptr, &unk, 1);
  png_set_unknown_chunk_location(handler.png_ptr, handler.info_ptr, 0, PNG_HAVE_IHDR);
#endif

  // Prepare dummy image data
  size_t rowbytes = png_get_rowbytes(handler.png_ptr, handler.info_ptr);
  std::vector<uint8_t> image_data(rowbytes * height, 0x7F);
  std::vector<png_bytep> row_pointers(height);
  for (size_t i = 0; i < height; ++i)
    row_pointers[i] = image_data.data() + i * rowbytes;

  png_set_rows(handler.png_ptr, handler.info_ptr, row_pointers.data());

  // Call the actual target
  png_write_png(handler.png_ptr, handler.info_ptr, PNG_TRANSFORM_IDENTITY, nullptr);

  return 0;
}













