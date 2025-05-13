#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>

#include "png.h"

// Memory write function for libpng
static void png_memory_write(png_structp png_ptr, png_bytep data, png_size_t length) {
  // This is a dummy write function - in a real fuzzer we might want to store this data
  // but for demonstration of the vulnerability, we can just discard it
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
  png_structp png_ptr;
  png_infop info_ptr;
  png_bytep row_data;
  png_uint_32 width = 999;  // Large width to maximize chances of overflow
  png_uint_32 height = 1;   // Just need one row
  int bit_depth = 16;       // Use 16-bit depth (2 bytes per channel)
  int color_type = PNG_COLOR_TYPE_RGBA;  // 4 channels
  
  // Calculate row size: width * channels * bytes_per_channel
  png_uint_32 row_size = width * 4 * (bit_depth / 8);
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
  // We allocate exactly row_size bytes, but libpng needs row_size + 1 for the filter byte
  row_data = (png_bytep)malloc(row_size);  // VULNERABILITY: Missing +1 for filter byte
  if (!row_data) {
      std::fprintf(stderr, "Out of memory\n");
      png_destroy_write_struct(&png_ptr, &info_ptr);
      return 1;
  }
  
  // Fill with some pattern data
  std::memset(row_data, 0xAA, row_size);
  
  // This call will cause a buffer overflow because png_write_row 
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