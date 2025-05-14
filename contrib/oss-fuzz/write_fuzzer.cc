#include <stdint.h>
#include <stddef.h>
#include <vector>
#include <string.h>
#include <png.h>
#include <setjmp.h>

//------------------------------------------------------------------------------
// Custom error & warning handlers for libpng
//------------------------------------------------------------------------------
void user_error_fn(png_structp png_ptr, png_const_charp error_msg) {
    // Grab our jmp_buf from the png error_ptr and longjmp back
    jmp_buf* jb = static_cast<jmp_buf*>(png_get_error_ptr(png_ptr));
    longjmp(*jb, 1);
}

void user_warning_fn(png_structp, png_const_charp) {
    // No-op: ignore libpng warnings
}

//------------------------------------------------------------------------------
// In-memory write implementation
//------------------------------------------------------------------------------
struct WriteBuffer {
    std::vector<uint8_t> data;
};

void custom_write(png_structp png_ptr, png_bytep data, png_size_t length) {
    WriteBuffer* buf = static_cast<WriteBuffer*>(png_get_io_ptr(png_ptr));
    buf->data.insert(buf->data.end(), data, data + length);
}

void custom_flush(png_structp) {
    // No-op
}

//------------------------------------------------------------------------------
// The fuzz entry point
//------------------------------------------------------------------------------
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Need at least 40 bytes for header + transforms
    if (size < 40) return 0;

    jmp_buf jmpbuf;
    WriteBuffer out_buffer;
    png_structp png_ptr   = nullptr;
    png_infop   info_ptr  = nullptr;

    // Wrap everything in a do/while so we can `break` out on error
    do {
        // Create write struct with our error handlers!
        png_ptr = png_create_write_struct(
            PNG_LIBPNG_VER_STRING,
            /* error_ptr */ &jmpbuf,
            /* error_fn   */ user_error_fn,
            /* warning_fn */ user_warning_fn
        );
        if (!png_ptr) break;

        info_ptr = png_create_info_struct(png_ptr);
        if (!info_ptr) {
            png_destroy_write_struct(&png_ptr, nullptr);
            break;
        }

        // On any libpng error, jump back here
        if (setjmp(jmpbuf)) {
            png_destroy_write_struct(&png_ptr, &info_ptr);
            break;
        }

        // Install our in‐memory write callbacks
        png_set_write_fn(png_ptr, &out_buffer, custom_write, custom_flush);

        // --- read IHDR fields from fuzzer data ---
        uint32_t width  = 1 + ((data[0] << 8) | data[1]) % 256;
        uint32_t height = 1 + ((data[2] << 8) | data[3]) % 256;

        static const int color_type_choices[] = {
            PNG_COLOR_TYPE_GRAY,
            PNG_COLOR_TYPE_GRAY_ALPHA,
            PNG_COLOR_TYPE_RGB,
            PNG_COLOR_TYPE_RGB_ALPHA,
            PNG_COLOR_TYPE_PALETTE
        };
        int color_type = color_type_choices[data[4] % 5];

        static const int bit_depth_choices[] = {1, 2, 4, 8, 16};
        int bit_depth = bit_depth_choices[data[5] % 5];

        // Skip invalid depth/type combos
        bool invalid = false;
        if ((color_type == PNG_COLOR_TYPE_PALETTE && bit_depth > 8) ||
            (color_type == PNG_COLOR_TYPE_RGB      && bit_depth != 8  && bit_depth != 16) ||
            (color_type == PNG_COLOR_TYPE_RGB_ALPHA&& bit_depth != 8  && bit_depth != 16) ||
            (color_type == PNG_COLOR_TYPE_GRAY &&
               !(bit_depth==1||bit_depth==2||bit_depth==4||bit_depth==8||bit_depth==16)) ||
            (color_type == PNG_COLOR_TYPE_GRAY_ALPHA && bit_depth != 8 && bit_depth != 16))
            invalid = true;
        if (invalid) break;

        int interlace_type = data[6] % 2;

        // Set IHDR
        png_set_IHDR(
            png_ptr, info_ptr,
            width, height,
            bit_depth, color_type, interlace_type,
            PNG_COMPRESSION_TYPE_BASE,
            PNG_FILTER_TYPE_BASE
        );

        // Compute rowbytes & guard against huge allocation
        png_size_t rowbytes = png_get_rowbytes(png_ptr, info_ptr);
        const size_t MAX_PIXELS = 16u << 20;  // 16 MiB
        if (rowbytes == 0 || (size_t)rowbytes * height > MAX_PIXELS) break;

        // Fill pixel buffer from the remainder of the input
        std::vector<uint8_t> image_data(rowbytes * height, 0);
        size_t copy_len = std::min((size_t)(size - 40), image_data.size());
        memcpy(image_data.data(), data + 40, copy_len);

        // Build row pointers
        std::vector<png_bytep> row_pointers(height);
        for (size_t y = 0; y < height; ++y) {
            row_pointers[y] = image_data.data() + y * rowbytes;
        }
        png_set_rows(png_ptr, info_ptr, row_pointers.data());

        // Extract transform flags
        uint32_t val = (uint32_t(data[36]) << 24)
                     | (uint32_t(data[37]) << 16)
                     | (uint32_t(data[38]) <<  8)
                     | (uint32_t(data[39])      );
        int transforms = 0;
        if (val & (1u <<  0)) transforms |= PNG_TRANSFORM_STRIP_16;
        if (val & (1u <<  1)) transforms |= PNG_TRANSFORM_STRIP_ALPHA;
        if (val & (1u <<  2)) transforms |= PNG_TRANSFORM_PACKING;
        if (val & (1u <<  3)) transforms |= PNG_TRANSFORM_PACKSWAP;
        if (val & (1u <<  4)) transforms |= PNG_TRANSFORM_EXPAND;
        if (val & (1u <<  5)) transforms |= PNG_TRANSFORM_INVERT_MONO;
        if (val & (1u <<  6)) transforms |= PNG_TRANSFORM_SHIFT;
        if (val & (1u <<  7)) transforms |= PNG_TRANSFORM_BGR;
        if (val & (1u <<  8)) transforms |= PNG_TRANSFORM_SWAP_ALPHA;
        if (val & (1u <<  9)) transforms |= PNG_TRANSFORM_INVERT_ALPHA;
        if (val & (1u << 10)) transforms |= PNG_TRANSFORM_SWAP_ENDIAN;

        // Finally: run the high-level write API
        png_write_png(png_ptr, info_ptr, transforms, nullptr);

    } while (0);

    // Clean up
    png_destroy_write_struct(&png_ptr, &info_ptr);
    return 0;
}





