#include <stdint.h>
#include <stddef.h>
#include <vector>
#include <string.h>
#include <png.h>
#include <setjmp.h>

struct WriteBuffer {
    std::vector<uint8_t> data;
};

// libpng error callback: on any error, longjmp back into the harness
static void png_error_cb(png_structp png_ptr, png_const_charp msg) {
    jmp_buf* jb = static_cast<jmp_buf*>(png_get_error_ptr(png_ptr));
    longjmp(*jb, 1);
}

// libpng warning callback: ignore
static void png_warning_cb(png_structp, png_const_charp) {
    // no-op
}

static void custom_write(png_structp png_ptr, png_bytep data, png_size_t length) {
    auto* buf = static_cast<WriteBuffer*>(png_get_io_ptr(png_ptr));
    buf->data.insert(buf->data.end(), data, data + length);
}

static void custom_flush(png_structp) {
    // no-op
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // we consume at least 40 bytes for IHDR + some pixel data
    if (size < 40) return 0;

    png_structp png_ptr = nullptr;
    png_infop   info_ptr = nullptr;
    jmp_buf     jmpbuf;
    WriteBuffer outbuf;

    do {
        // 1) Create the write struct, installing our error/warning handlers
        png_ptr = png_create_write_struct(
            PNG_LIBPNG_VER_STRING,
            &jmpbuf,
            png_error_cb,
            png_warning_cb
        );
        if (!png_ptr) break;

        // 2) Create info struct
        info_ptr = png_create_info_struct(png_ptr);
        if (!info_ptr) {
            png_destroy_write_struct(&png_ptr, nullptr);
            break;
        }

        // 3) If libpng signals an error, jump back here
        if (setjmp(jmpbuf)) {
            png_destroy_write_struct(&png_ptr, &info_ptr);
            break;
        }

        // 4) Hook up our write‐to‐vector callbacks
        png_set_write_fn(png_ptr, &outbuf, custom_write, custom_flush);

        // 5) Parse IHDR fields from the first few bytes
        uint32_t width  = 1 + ((data[0]<<8 | data[1]) % 256);
        uint32_t height = 1 + ((data[2]<<8 | data[3]) % 256);

        static const int CTs[] = {
            PNG_COLOR_TYPE_GRAY,
            PNG_COLOR_TYPE_GRAY_ALPHA,
            PNG_COLOR_TYPE_RGB,
            PNG_COLOR_TYPE_RGB_ALPHA,
            PNG_COLOR_TYPE_PALETTE
        };
        int color_type = CTs[data[4] % 5];

        static const int BDs[] = {1,2,4,8,16};
        int bit_depth = BDs[data[5] % 5];

        // 6) Filter out invalid color‐depth combinations
        bool bad = false;
        if ((color_type == PNG_COLOR_TYPE_PALETTE    && bit_depth > 8)  ||
            (color_type == PNG_COLOR_TYPE_RGB        && bit_depth!=8&&bit_depth!=16) ||
            (color_type == PNG_COLOR_TYPE_RGB_ALPHA  && bit_depth!=8&&bit_depth!=16) ||
            (color_type == PNG_COLOR_TYPE_GRAY       && bit_depth!=1&&bit_depth!=2&&bit_depth!=4&&bit_depth!=8&&bit_depth!=16) ||
            (color_type == PNG_COLOR_TYPE_GRAY_ALPHA && bit_depth!=8&&bit_depth!=16))
            bad = true;
        if (bad) break;

        int interlace = data[6] % 2;

        // 7) Write IHDR
        png_set_IHDR(png_ptr, info_ptr,
                     width, height,
                     bit_depth,
                     color_type,
                     interlace,
                     PNG_COMPRESSION_TYPE_BASE,
                     PNG_FILTER_TYPE_BASE);

        // 8) If it's a palette image, give it a minimal two‐entry PLTE
        if (color_type == PNG_COLOR_TYPE_PALETTE) {
            png_color pal[2] = {{0,0,0},{255,255,255}};
            png_set_PLTE(png_ptr, info_ptr, pal, 2);
        }

        // 9) Build our row pointers
        png_size_t rowbytes = png_get_rowbytes(png_ptr, info_ptr);
        const size_t MAX_PIXELS = 16u << 20;  // cap 16 MiB
        if (rowbytes == 0 || (size_t)rowbytes * height > MAX_PIXELS)
            break;

        std::vector<uint8_t> image(rowbytes * height);
        size_t to_copy = std::min(image.size(), size - 40);
        memcpy(image.data(), data + 40, to_copy);

        std::vector<png_bytep> rows(height);
        for (uint32_t y = 0; y < height; y++)
            rows[y] = image.data() + (size_t)y * rowbytes;
        png_set_rows(png_ptr, info_ptr, rows.data());

        // 10) Write it out with *no transforms* (pure write_png path)
        png_write_png(png_ptr, info_ptr,
                      PNG_TRANSFORM_IDENTITY,
                      nullptr);

    } while (0);

    // 11) Clean up
    png_destroy_write_struct(&png_ptr, &info_ptr);
    return 0;
}









