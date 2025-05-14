#include <stddef.h>
#include <stdint.h>
#include <vector>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>

#include "png.h"

// Custom error function to avoid abort()
void custom_error_fn(png_structp png_ptr, png_const_charp error_msg) {
    longjmp(png_jmpbuf(png_ptr), 1);
}

// Custom write function that just discards output
void custom_write(png_structp png_ptr, png_bytep data, png_size_t length) {
    (void)png_ptr;
    (void)data;
    (void)length;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;

    // Initialize png write struct
    png_structp png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
    if (!png_ptr) return 0;

    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_write_struct(&png_ptr, nullptr);
        return 0;
    }

    // Set custom error handler
    png_set_error_fn(png_ptr, nullptr, custom_error_fn, nullptr);

    if (setjmp(png_jmpbuf(png_ptr))) {
        // If libpng triggers an error
        png_destroy_write_struct(&png_ptr, &info_ptr);
        return 0;
    }

    // Set custom output function (we discard the output)
    png_set_write_fn(png_ptr, nullptr, custom_write, nullptr);

    // Hardcoded image parameters for now (simplified but valid)
    png_uint_32 width = 1;
    png_uint_32 height = 1;
    int bit_depth = 8;
    int color_type = PNG_COLOR_TYPE_RGB;

    png_set_IHDR(png_ptr, info_ptr, width, height, bit_depth,
                 color_type, PNG_INTERLACE_NONE,
                 PNG_COMPRESSION_TYPE_BASE, PNG_FILTER_TYPE_BASE);

    // Write the image info
    png_write_info(png_ptr, info_ptr);

    // Prepare a simple row (RGB)
    std::vector<uint8_t> row(3 * width, 0xFF);
    png_bytep row_ptrs[1] = { row.data() };

    // Write image data
    png_write_image(png_ptr, row_ptrs);

    // Write end (also wrapped under setjmp above)
    png_write_end(png_ptr, nullptr);

    // Cleanup
    png_destroy_write_struct(&png_ptr, &info_ptr);
    return 0;
}











