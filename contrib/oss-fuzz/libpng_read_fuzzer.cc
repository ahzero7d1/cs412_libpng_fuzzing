#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "png.h"

struct BufState {
  const uint8_t* data;
  size_t bytes_left;
};

struct PngHandler {
  png_structp png_ptr = nullptr;
  png_infop info_ptr = nullptr;
  png_infop end_info_ptr = nullptr;
  png_bytep row_ptr = nullptr;
  BufState* buf_state = nullptr;

  ~PngHandler() {
    if (row_ptr) png_free(png_ptr, row_ptr);
    if (end_info_ptr)
      png_destroy_read_struct(&png_ptr, &info_ptr, &end_info_ptr);
    else if (info_ptr)
      png_destroy_read_struct(&png_ptr, &info_ptr, nullptr);
    else if (png_ptr)
      png_destroy_read_struct(&png_ptr, nullptr, nullptr);
    delete buf_state;
  }
};

void* limited_malloc(png_structp, png_alloc_size_t size) {
  return (size > 8000000) ? nullptr : malloc(size);
}

void default_free(png_structp, png_voidp ptr) {
  free(ptr);
}

void user_read_data(png_structp png_ptr, png_bytep out_data, size_t length) {
  auto* state = static_cast<BufState*>(png_get_io_ptr(png_ptr));
  if (length > state->bytes_left) png_error(png_ptr, "read overflow");
  memcpy(out_data, state->data, length);
  state->data += length;
  state->bytes_left -= length;
}

static constexpr int kHeaderSize = 8;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < kHeaderSize) return 0;
  if (png_sig_cmp(data, 0, kHeaderSize)) return 0;

  PngHandler handler;
  handler.png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!handler.png_ptr) return 0;

  png_set_mem_fn(handler.png_ptr, nullptr, limited_malloc, default_free);
  png_set_crc_action(handler.png_ptr, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE);
  png_set_option(handler.png_ptr, PNG_SKIP_sRGB_CHECK_PROFILE, PNG_OPTION_ON);

  handler.info_ptr = png_create_info_struct(handler.png_ptr);
  handler.end_info_ptr = png_create_info_struct(handler.png_ptr);
  if (!handler.info_ptr || !handler.end_info_ptr) return 0;

  handler.buf_state = new BufState{ data + kHeaderSize, size - kHeaderSize };
  png_set_read_fn(handler.png_ptr, handler.buf_state, user_read_data);
  png_set_sig_bytes(handler.png_ptr, kHeaderSize);

  if (setjmp(png_jmpbuf(handler.png_ptr))) return 0;

  png_read_info(handler.png_ptr, handler.info_ptr);

  png_uint_32 width, height;
  int bit_depth, color_type, interlace, compression, filter;
  if (!png_get_IHDR(handler.png_ptr, handler.info_ptr,
                    &width, &height, &bit_depth, &color_type,
                    &interlace, &compression, &filter)) {
    return 0;
  }

  if (width && height > 100000000 / width) return 0;

  // Diverse transform stack to hit pngtrans.c and pngrtran.c
  png_set_strip_16(handler.png_ptr);
  png_set_packing(handler.png_ptr);
  png_set_expand(handler.png_ptr);
  png_set_scale_16(handler.png_ptr);
  png_set_gray_to_rgb(handler.png_ptr);
  png_set_filler(handler.png_ptr, 0xFF, PNG_FILLER_AFTER);
  png_set_invert_alpha(handler.png_ptr);
  png_set_bgr(handler.png_ptr);
  png_set_swap(handler.png_ptr);
  png_set_invert_mono(handler.png_ptr);

  int passes = png_set_interlace_handling(handler.png_ptr);
  png_read_update_info(handler.png_ptr, handler.info_ptr);

  // Allocate one row
  handler.row_ptr = png_malloc(handler.png_ptr,
    png_get_rowbytes(handler.png_ptr, handler.info_ptr));
  if (!handler.row_ptr) return 0;

  for (int pass = 0; pass < passes; ++pass) {
    for (png_uint_32 y = 0; y < height; ++y) {
      png_read_row(handler.png_ptr, handler.row_ptr, nullptr);
      if (y % 3 == 0) png_read_row(handler.png_ptr, nullptr, nullptr); // Dummy
    }
  }

  png_read_end(handler.png_ptr, handler.end_info_ptr);

  // Access as many pngget.c APIs as possible
  png_get_bit_depth(handler.png_ptr, handler.info_ptr);
  png_get_color_type(handler.png_ptr, handler.info_ptr);
  png_get_filter_type(handler.png_ptr, handler.info_ptr);
  png_get_compression_type(handler.png_ptr, handler.info_ptr);
  png_get_interlace_type(handler.png_ptr, handler.info_ptr);
  png_get_pixel_aspect_ratio(handler.png_ptr, handler.info_ptr);
  png_get_x_offset_pixels(handler.png_ptr, handler.info_ptr);
  png_get_y_offset_pixels(handler.png_ptr, handler.info_ptr);
  png_get_valid(handler.png_ptr, handler.info_ptr, PNG_INFO_tIME);

  png_textp text_ptr;
  int num_text;
  if (png_get_text(handler.png_ptr, handler.info_ptr, &text_ptr, &num_text)) {
    for (int i = 0; i < num_text; ++i) {
      volatile auto* key = text_ptr[i].key;
      volatile auto* val = text_ptr[i].text;
    }
  }

  png_get_gAMA(handler.png_ptr, handler.info_ptr, nullptr);
  png_get_sBIT(handler.png_ptr, handler.info_ptr, nullptr);
  png_get_sRGB(handler.png_ptr, handler.info_ptr, nullptr);
  png_get_cHRM(handler.png_ptr, handler.info_ptr,
               nullptr, nullptr, nullptr, nullptr,
               nullptr, nullptr, nullptr);
  png_get_tIME(handler.png_ptr, handler.info_ptr, nullptr);
  png_get_PLTE(handler.png_ptr, handler.info_ptr, nullptr, nullptr);

  // Optional: simplified API (separate coverage group)
#ifdef PNG_SIMPLIFIED_READ_SUPPORTED
  if (data[0] % 2 == 0) {
    png_image image;
    memset(&image, 0, sizeof image);
    image.version = PNG_IMAGE_VERSION;
    if (png_image_begin_read_from_memory(&image, data, size)) {
      image.format = PNG_FORMAT_RGBA;
      std::vector<png_byte> buffer(PNG_IMAGE_SIZE(image));
      png_image_finish_read(&image, nullptr, buffer.data(), 0, nullptr);
    }
  }
#endif

  return 0;
}
