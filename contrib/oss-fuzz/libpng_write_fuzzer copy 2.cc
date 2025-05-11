// libpng_write_fuzzer.cc

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <setjmp.h> 

#define PNG_INTERNAL // May be needed for some internal access

#include "png.h"

// Dummy write function for fuzzing - discards output
void user_write_data(png_structp png_ptr, png_bytep data, png_size_t length) {
  // Do nothing with the data - we are just testing libpng's writing logic.
  (void)png_ptr;
  (void)data;
  (void)length;
}

// Dummy flush function
void user_flush_data(png_structp png_ptr) {
  // Do nothing on flush
  (void)png_ptr;
}

// Custom memory allocator to limit large allocations
void* limited_malloc(png_structp, png_alloc_size_t size) {
  // Limit allocations to avoid OOM issues during fuzzing.
  // This limit is arbitrary but should be reasonable for typical PNG operations.
  if (size > 16000000) // 16MB limit
    return nullptr;

  return malloc(size);
}

void default_free(png_structp, png_voidp ptr) {
  return free(ptr);
}
struct BufState {
  const uint8_t* data;
  size_t bytes_left;
};
// Structure to hold libpng pointers and manage cleanup
struct PngObjectHandler {
  png_structp png_ptr = nullptr;
  png_infop info_ptr = nullptr;
  png_voidp row_ptr = nullptr;
  BufState* buf_state = nullptr;

  ~PngObjectHandler() {
    if (row_ptr)
      png_free(png_ptr, row_ptr);
    if (info_ptr)
      png_destroy_write_struct(&png_ptr, &info_ptr);
    else
      png_destroy_write_struct(&png_ptr, nullptr);
    delete buf_state;
  }
};

// Custom error handler for libpng
static jmp_buf jmpbuf_g;
static void user_error_fn(png_structp png_ptr, png_const_charp msg) {
  // We can print the error message for debugging
  fprintf(stderr, "libpng error: %s\n", msg);
  // Long jump back to the setjmp point in the fuzzer entry function
  longjmp(jmpbuf_g, 1);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 8) { // Need at least some data for parameters
    return 0;
  }
  // https://github.com/google/oss-fuzz/issues/2111
    png_image image;
    memset(&image, 0, sizeof(image));
    image.version = PNG_IMAGE_VERSION;
    png_image_begin_read_from_memory(&image, data, sizeof(data));
  return 0;
}