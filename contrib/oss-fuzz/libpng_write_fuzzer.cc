#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>

#include "png.h"

// This is the crash sample that triggered the heap buffer overflow
const uint8_t kCrashData[] = {
  // Width = 999 (0x03, 0xE7)
  0x03, 0xE7,
  // Height = 1
  0x00, 0x01,
  // Color type = 6 (RGBA)
  0x06,
  // Bit depth = 8
  0x08,
  // Just some data to fill the rest
  0xAA, 0xBB, 0xCC, 0xDD
};

// Memory write function for libpng
static void png_memory_write(png_structp png_ptr, png_bytep data, png_size_t length) {
  // This is a dummy write function - we discard the output
  (void)png_ptr;  // Unused
  (void)data;     // Unused
  (void)length;   // Unused
}

// Dummy flush function
static void png_memory_flush(png_structp png_ptr) {
  // Do nothing
  (void)png_ptr;  // Unused
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Use our hard-coded crash data
  data = kCrashData;
  size = sizeof(kCrashData);

  png_structp png_ptr;
  png_infop info_ptr;
  
  // Extract parameters from crash data
  uint32_t width = (data[0] << 8) | data[1];    // 999
  uint32_t height = (data[2] << 8) | data[3];   // 1
  int color_type = data[4];                     // 6 (RGBA)
  int bit_depth = data[5];                      // 8
  
  std::printf("Creating image with width=%u, height=%u, color_type=%d, bit_depth=%d\n", 
               width, height, color_type, bit_depth);
  
  // Calculate row size in bytes (width * channels * bytes_per_channel)
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
  
  // Here's the key vulnerability:
  // Allocate precisely row_size bytes but libpng needs row_size + 1 for the filter byte
  png_bytep row_data = (png_bytep)malloc(row_size);  // VULNERABILITY: Missing +1 for filter byte
  if (!row_data) {
      std::fprintf(stderr, "Out of memory\n");
      png_destroy_write_struct(&png_ptr, &info_ptr);
      return 1;
  }
  
  // Fill with pattern data
  std::memset(row_data, 0xAA, row_size);
  
  // This call will cause a heap buffer overflow because png_write_row 
  // tries to use row_data[-1] as the filter byte
  std::printf("About to write row (buffer overflow will occur here)\n");
  png_write_row(png_ptr, row_data);
  
  // Finish writing PNG (we won't get here if overflow crashes)
  png_write_end(png_ptr, NULL);
  
  // Cleanup
  free(row_data);
  png_destroy_write_struct(&png_ptr, &info_ptr);
  
  std::printf("Successfully completed (should not reach here if overflow detected)\n");
  return 0;
}