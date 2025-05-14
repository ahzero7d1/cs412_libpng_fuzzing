#include <stdint.h>
#include <stddef.h>
#include <vector>
#include <string.h>
#include <png.h>
#include <setjmp.h>

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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 40) return 0;  // Ensure enough data

    png_structp png_ptr = nullptr;
    png_infop info_ptr = nullptr;
    jmp_buf jmpbuf;
    WriteBuffer out_buffer;

    do {
        png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, &jmpbuf, nullptr, nullptr);
        if (!png_ptr) break;

        info_ptr = png_create_info_struct(png_ptr);
        if (!info_ptr) {
            png_destroy_write_struct(&png_ptr, nullptr);
            break;
        }

        if (setjmp(jmpbuf)) {
            png_destroy_write_struct(&png_ptr, &info_ptr);
            break;
        }

        png_set_write_fn(png_ptr, &out_buffer, custom_write, custom_flush);

        // Parse image metadata safely
        uint32_t width  = 1 + (data[0] << 8 | data[1]) % 256;
        uint32_t height = 1 + (data[2] << 8 | data[3]) % 256;

        int color_type_choices[] = {
            PNG_COLOR_TYPE_GRAY,
            PNG_COLOR_TYPE_GRAY_ALPHA,
            PNG_COLOR_TYPE_RGB,
            PNG_COLOR_TYPE_RGB_ALPHA,
            PNG_COLOR_TYPE_PALETTE
        };
        int color_type = color_type_choices[data[4] % 5];

        int bit_depth_choices[] = {1, 2, 4, 8, 16};
        int bit_depth = bit_depth_choices[data[5] % 5];

        // Filter invalid bit depth + color type combinations
        bool invalid = false;
        if ((color_type == PNG_COLOR_TYPE_PALETTE && bit_depth > 8) ||
            (color_type == PNG_COLOR_TYPE_RGB && bit_depth != 8 && bit_depth != 16) ||
            (color_type == PNG_COLOR_TYPE_RGB_ALPHA && bit_depth != 8 && bit_depth != 16) ||
            (color_type == PNG_COLOR_TYPE_GRAY && (bit_depth != 1 && bit_depth != 2 &&
                                                    bit_depth != 4 && bit_depth != 8 && bit_depth != 16)) ||
            (color_type == PNG_COLOR_TYPE_GRAY_ALPHA && bit_depth != 8 && bit_depth != 16)) {
            invalid = true;
        }
        if (invalid) break;

        int interlace_type = data[6] % 2;

        // Set IHDR
        png_set_IHDR(png_ptr, info_ptr, width, height, bit_depth,
                     color_type, interlace_type,
                     PNG_COMPRESSION_TYPE_BASE, PNG_FILTER_TYPE_BASE);

        png_size_t rowbytes = png_get_rowbytes(png_ptr, info_ptr);
        const size_t max_size = 16 * 1024 * 1024;
        if (rowbytes == 0 || rowbytes * height > max_size) break;

        std::vector<uint8_t> image_data(rowbytes * height, 0);
        if (size > 40) {
            memcpy(image_data.data(), data + 40, std::min(size - 40, image_data.size()));
        }

        std::vector<png_bytep> row_pointers(height);
        for (size_t i = 0; i < height; ++i)
            row_pointers[i] = image_data.data() + i * rowbytes;
        png_set_rows(png_ptr, info_ptr, row_pointers.data());

        // Extract transform flags from fuzz input
        int transforms = 0;
        uint32_t val = ((data[36] << 24) | (data[37] << 16) |
                        (data[38] << 8) | data[39]);
        if (val & (1 << 0)) transforms |= PNG_TRANSFORM_STRIP_16;
        if (val & (1 << 1)) transforms |= PNG_TRANSFORM_STRIP_ALPHA;
        if (val & (1 << 2)) transforms |= PNG_TRANSFORM_PACKING;
        if (val & (1 << 3)) transforms |= PNG_TRANSFORM_PACKSWAP;
        if (val & (1 << 4)) transforms |= PNG_TRANSFORM_EXPAND;
        if (val & (1 << 5)) transforms |= PNG_TRANSFORM_INVERT_MONO;
        if (val & (1 << 6)) transforms |= PNG_TRANSFORM_SHIFT;
        if (val & (1 << 7)) transforms |= PNG_TRANSFORM_BGR;
        if (val & (1 << 8)) transforms |= PNG_TRANSFORM_SWAP_ALPHA;
        if (val & (1 << 9)) transforms |= PNG_TRANSFORM_INVERT_ALPHA;
        if (val & (1 << 10)) transforms |= PNG_TRANSFORM_SWAP_ENDIAN;

        // Final write
        png_write_png(png_ptr, info_ptr, transforms, nullptr);

    } while (0);

    png_destroy_write_struct(&png_ptr, &info_ptr);
    return 0;
}


