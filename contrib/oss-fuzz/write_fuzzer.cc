#include <stdint.h>
#include <stddef.h>
#include <vector>
#include <string.h>
#include <png.h>
#include <setjmp.h>
#include <stdio.h>

struct FuzzingContext {
    std::vector<uint8_t> buffer;
    jmp_buf jmpbuf;
};

void custom_write_fn(png_structp png_ptr, png_bytep data, png_size_t length) {
    FuzzingContext* ctx = static_cast<FuzzingContext*>(png_get_io_ptr(png_ptr));
    ctx->buffer.insert(ctx->buffer.end(), data, data + length);
}

void custom_flush_fn(png_structp) {}

void custom_error_fn(png_structp png_ptr, png_const_charp msg) {
    FuzzingContext* ctx = static_cast<FuzzingContext*>(png_get_error_ptr(png_ptr));
    longjmp(ctx->jmpbuf, 1);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 64) return 0;

    FuzzingContext ctx;
    png_structp png_ptr = nullptr;
    png_infop info_ptr = nullptr;

    if ((png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, &ctx, custom_error_fn, nullptr)) == nullptr)
        return 0;
    if ((info_ptr = png_create_info_struct(png_ptr)) == nullptr) {
        png_destroy_write_struct(&png_ptr, nullptr);
        return 0;
    }

    if (setjmp(ctx.jmpbuf)) {
        png_destroy_write_struct(&png_ptr, &info_ptr);
        return 0;
    }

    png_set_write_fn(png_ptr, &ctx, custom_write_fn, custom_flush_fn);

    // Extract valid metadata
    uint32_t width = 1 + (data[0] << 8 | data[1]);
    uint32_t height = 1 + (data[2] << 8 | data[3]);

    int color_types[] = {PNG_COLOR_TYPE_GRAY, PNG_COLOR_TYPE_RGB, PNG_COLOR_TYPE_RGBA};
    int bit_depths[] = {8, 16};

    int color_type = color_types[data[4] % 3];
    int bit_depth = bit_depths[data[5] % 2];

    // Reject unsupported combinations
    if ((color_type == PNG_COLOR_TYPE_GRAY && bit_depth != 8 && bit_depth != 16) ||
        (color_type == PNG_COLOR_TYPE_RGB && bit_depth != 8 && bit_depth != 16) ||
        (color_type == PNG_COLOR_TYPE_RGBA && bit_depth != 8 && bit_depth != 16)) {
        png_destroy_write_struct(&png_ptr, &info_ptr);
        return 0;
    }

    png_set_IHDR(png_ptr, info_ptr, width, height, bit_depth, color_type,
                 PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_BASE, PNG_FILTER_TYPE_BASE);

    png_size_t rowbytes = png_get_rowbytes(png_ptr, info_ptr);
    if (rowbytes == 0 || rowbytes > 1 << 20) {
        png_destroy_write_struct(&png_ptr, &info_ptr);
        return 0;
    }

    std::vector<uint8_t> image_data(rowbytes * height);
    memcpy(image_data.data(), data + 6, std::min(size - 6, image_data.size()));

    std::vector<png_bytep> row_pointers(height);
    for (size_t i = 0; i < height; i++) {
        row_pointers[i] = image_data.data() + i * rowbytes;
    }
    png_set_rows(png_ptr, info_ptr, row_pointers.data());

    // Call png_write_png
    png_write_png(png_ptr, info_ptr, PNG_TRANSFORM_IDENTITY, nullptr);

    png_destroy_write_struct(&png_ptr, &info_ptr);
    return 0;
}










