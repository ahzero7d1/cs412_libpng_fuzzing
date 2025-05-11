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

  PngObjectHandler png_handler;

  // Use setjmp for error handling
  if (setjmp(jmpbuf_g)) {
    // If we jump here, a libpng error occurred. The PngObjectHandler destructor
    // will handle cleanup.
    return 0;
  }

  // Create libpng write structures
  png_handler.png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING,
                                                nullptr, user_error_fn, nullptr);
  if (!png_handler.png_ptr) {
    return 0; // Allocation failed
  }

 
  png_handler.info_ptr = png_create_info_struct(png_handler.png_ptr);
  if (!png_handler.info_ptr) {
    return 0; // Allocation failed (PngObjectHandler destructor cleans png_ptr)
  }

  uint32_t width = 0;
  png_handler.info_ptr->width = width;
  png_handler.info_ptr->color_type = PNG_COLOR_TYPE_GRAY;
  png_handler.info_ptr->bit_depth = 16;
  png_handler.info_ptr->channels = 2;
  png_handler.info_ptr->height = 1;
  png_handler.info_ptr->pixel_depth = png_handler.info_ptr->channels * png_handler.info_ptr->bit_depth;
  png_handler.info_ptr->rowbytes = PNG_ROWBYTES(png_handler.info_ptr->pixel_depth, png_handler.info_ptr->width);

  png_bytep *image = malloc(png_handler.info_ptr->height * sizeof(png_bytep));
  for (unsigned i = 0; i < info->height; i++) {
      image[i] = calloc(info->rowbytes, 1);
  }
  png_set_rows(png, png_handler.info_ptr, image);

  int transforms = PNG_TRANSFORM_STRIP_FILLER_AFTER | \
                   PNG_TRANSFORM_INVERT_MONO;
  png_write_png(png, png_handler.info_ptr, transforms, NULL);


  png_write_end(png_handler.png_ptr, png_handler.info_ptr);

  return 0;
}