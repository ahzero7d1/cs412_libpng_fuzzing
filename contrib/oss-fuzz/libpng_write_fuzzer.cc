#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "png.h"

struct BufState {
  uint8_t* data;
  size_t size;
  size_t position;
};

struct PngHandler {
  png_structp png_ptr = nullptr;
  png_infop info_ptr = nullptr;
  png_bytep row_ptr = nullptr;
  BufState* buf_state = nullptr;
  
  ~PngHandler() {
    if (row_ptr) png_free(png_ptr, row_ptr);
    if (info_ptr)
      png_destroy_write_struct(&png_ptr, &info_ptr);
    else if (png_ptr)
      png_destroy_write_struct(&png_ptr, nullptr);
    
    if (buf_state) {
      free(buf_state->data); // Free the data buffer
      delete buf_state;
    }
  }
};

void* limited_malloc(png_structp, png_alloc_size_t size) {
  return (size > 8000000) ? nullptr : malloc(size);
}

void default_free(png_structp, png_voidp ptr) {
  free(ptr);
}

void user_write_data(png_structp png_ptr, png_bytep data, size_t length) {
  auto* state = static_cast<BufState*>(png_get_io_ptr(png_ptr));
  if (state->position + length > state->size) {
    // Reallocate if needed
    size_t new_size = state->size * 2;
    if (new_size < state->position + length)
      new_size = state->position + length;
    
    uint8_t* new_data = static_cast<uint8_t*>(realloc(state->data, new_size));
    if (new_data == nullptr) {
      png_error(png_ptr, "write buffer allocation error");
      return;
    }
    
    state->data = new_data;
    state->size = new_size;
  }
  
  memcpy(state->data + state->position, data, length);
  state->position += length;
}

void user_flush_data(png_structp png_ptr) {
  // No-op for memory buffer
  (void)png_ptr;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 16) return 0; // Need minimum data to work with

  PngHandler handler;
  
  // Create write structures
  handler.png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!handler.png_ptr) return 0;
  
  // Set custom memory handlers
  png_set_mem_fn(handler.png_ptr, nullptr, limited_malloc, default_free);
  
  handler.info_ptr = png_create_info_struct(handler.png_ptr);
  if (!handler.info_ptr) return 0;
  
  // Set up error handling
  if (setjmp(png_jmpbuf(handler.png_ptr))) return 0;
  
  // Initialize BufState for output buffer
  handler.buf_state = new BufState();
  handler.buf_state->data = static_cast<uint8_t*>(malloc(4096)); // Initial size
  if (!handler.buf_state->data) return 0;
  handler.buf_state->size = 4096;
  handler.buf_state->position = 0;
  
  // Set up the output control
  png_set_write_fn(handler.png_ptr, handler.buf_state, user_write_data, user_flush_data);
  
  // Extract basic image parameters from the fuzz data
  uint32_t width = (data[0] << 8) | data[1];
  uint32_t height = (data[2] << 8) | data[3];
  
  // Keep dimensions reasonable for fuzzing
  width = (width % 1000) + 1;
  height = (height % 1000) + 1;
  
  // Set color type and bit depth based on fuzz data
  int color_type = data[4] % 7; // 0-6 are valid color types
  if (color_type == 1 || color_type == 5) color_type = 0; // Skip invalid types
  
  int bit_depth;
  switch (color_type) {
    case PNG_COLOR_TYPE_PALETTE:
      bit_depth = 1 << (data[5] % 4); // 1, 2, 4, or 8
      if (bit_depth > 8) bit_depth = 8;
      break;
    case PNG_COLOR_TYPE_GRAY:
      bit_depth = 1 << (data[5] % 4); // 1, 2, 4, 8, or 16
      if (data[6] & 1) bit_depth = 16;
      break;
    default:
      bit_depth = (data[5] & 1) ? 8 : 16; // 8 or 16 for other types
      break;
  }
  
  // Set IHDR
  png_set_IHDR(handler.png_ptr, handler.info_ptr, width, height, bit_depth, color_type,
               PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_BASE, PNG_FILTER_TYPE_BASE);
  
  // Optional: Set random text chunks if enough input data
  if (size > 32 && (data[7] & 1)) {
    png_text text_ptr;
    text_ptr.compression = PNG_TEXT_COMPRESSION_NONE;
    text_ptr.key = const_cast<char*>("Title");
    text_ptr.text = const_cast<char*>("Fuzzing libpng");
    text_ptr.text_length = 14;
    png_set_text(handler.png_ptr, handler.info_ptr, &text_ptr, 1);
  }
  
  // If color type is palette, set a palette
  if (color_type == PNG_COLOR_TYPE_PALETTE) {
    int num_palette = (data[8] % 256) + 1;
    
    // Use png_malloc instead of std::vector to avoid leaks
    png_colorp palette = (png_colorp)png_malloc(handler.png_ptr, num_palette * sizeof(png_color));
    
    for (int i = 0; i < num_palette && (i*3 + 16) < size; i++) {
      palette[i].red = data[9 + i*3];
      palette[i].green = data[10 + i*3];
      palette[i].blue = data[11 + i*3];
    }
    
    png_set_PLTE(handler.png_ptr, handler.info_ptr, palette, num_palette);
    
    // Add transparency for some palette entries if data available
    if (size > 32 + num_palette && (data[12] & 1)) {
      int num_trans = data[13] % num_palette;
      
      // Use png_malloc for transparent values too
      png_bytep trans = (png_bytep)png_malloc(handler.png_ptr, num_trans);
      
      for (int i = 0; i < num_trans && (i + 32) < size; i++) {
        trans[i] = data[14 + i];
      }
      
      png_set_tRNS(handler.png_ptr, handler.info_ptr, trans, num_trans, nullptr);
      
      // No need to free trans - libpng will handle it
    }
  }
  
  // Write PNG info
  png_write_info(handler.png_ptr, handler.info_ptr);
  
  // For 16-bit depth, set swap on little-endian machines
  if (bit_depth == 16) {
    png_uint_16 test = 0x0001;
    if (*(png_bytep)&test) {
      png_set_swap(handler.png_ptr);
    }
  }
  
  // Set up transformations
  if (data[15] & 1) {
    png_set_packing(handler.png_ptr);
  }
  
  // Allocate row buffer
  png_uint_32 rowbytes = png_get_rowbytes(handler.png_ptr, handler.info_ptr);
  handler.row_ptr = static_cast<png_bytep>(png_malloc(handler.png_ptr, rowbytes));
  if (!handler.row_ptr) return 0;
  
  // Write image data
  size_t data_pos = 16;
  for (uint32_t y = 0; y < height; y++) {
    // Fill row with data from the fuzzer input
    for (uint32_t x = 0; x < rowbytes; x++) {
      handler.row_ptr[x] = (data_pos < size) ? data[data_pos++] : (data_pos + x) & 0xFF;
    }
    
    png_write_row(handler.png_ptr, handler.row_ptr);
  }
  
  // Finish writing
  png_write_end(handler.png_ptr, nullptr);
  
  // Clean up is handled by the PngHandler destructor
  return 0;
}