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
    auto* buf = static_cast<WriteBuffer*>(png_get_io_ptr(png_ptr));
    buf->data.insert(buf->data.end(), data, data + length);
}
void custom_flush(png_structp) {}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 40) return 0;

    png_structp png_ptr = png_create_write_struct(
        PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
    if (!png_ptr) return 0;

    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_write_struct(&png_ptr, nullptr);
        return 0;
    }

    // Catch any libpng errors
    if (setjmp(png_jmpbuf(png_ptr))) {
        png_destroy_write_struct(&png_ptr, &info_ptr);
        return 0;
    }

    WriteBuffer out;
    png_set_write_fn(png_ptr, &out, custom_write, custom_flush);

    // Pick a safe image size
    uint32_t W = 1 + ((data[0] << 8 | data[1]) % 256);
    uint32_t H = 1 + ((data[2] << 8 | data[3]) % 256);

    // Only the four non‐palette types
    int types[] = {
      PNG_COLOR_TYPE_GRAY,
      PNG_COLOR_TYPE_GRAY_ALPHA,
      PNG_COLOR_TYPE_RGB,
      PNG_COLOR_TYPE_RGB_ALPHA
    };
    int color_type = types[data[4] % 4];

    int depths[] = {1, 2, 4, 8, 16};
    int bit_depth = depths[data[5] % 5];

    // Filter out impossible combos
    bool bad = false;
    if ((color_type == PNG_COLOR_TYPE_RGB ||
         color_type == PNG_COLOR_TYPE_RGB_ALPHA) &&
        bit_depth != 8 && bit_depth != 16) bad = true;
    if ((color_type == PNG_COLOR_TYPE_GRAY ||
         color_type == PNG_COLOR_TYPE_GRAY_ALPHA) &&
        bit_depth != 1 && bit_depth != 2 &&
        bit_depth != 4 && bit_depth != 8 && bit_depth != 16) bad = true;
    if (bad) {
        png_destroy_write_struct(&png_ptr, &info_ptr);
        return 0;
    }

    int interlace = data[6] % 2;
    png_set_IHDR(png_ptr, info_ptr, W, H, bit_depth,
                 color_type, interlace,
                 PNG_COMPRESSION_TYPE_BASE, PNG_FILTER_TYPE_BASE);

    // Build a zero‐filled image buffer
    png_size_t rowbytes = png_get_rowbytes(png_ptr, info_ptr);
    const size_t MAX = 16<<20;
    if (rowbytes == 0 || (size_t)rowbytes * H > MAX) {
        png_destroy_write_struct(&png_ptr, &info_ptr);
        return 0;
    }

    std::vector<uint8_t> img(rowbytes * H, 0);
    if (size > 40) {
        memcpy(img.data(),
               data + 40,
               std::min(img.size(), size - 40));
    }

    std::vector<png_bytep> rows(H);
    for (unsigned i = 0; i < H; i++)
        rows[i] = img.data() + i * rowbytes;
    png_set_rows(png_ptr, info_ptr, rows.data());

    // Decode your 32‐bit transform mask
    uint32_t mask = (data[36] << 24) | (data[37] << 16)
                  | (data[38] <<  8) |  data[39];
    int transforms = 0;
    if (mask & 1)   transforms |= PNG_TRANSFORM_STRIP_16;
    if (mask & (1<<1)) transforms |= PNG_TRANSFORM_STRIP_ALPHA;
    if (mask & (1<<2)) transforms |= PNG_TRANSFORM_PACKING;
    if (mask & (1<<3)) transforms |= PNG_TRANSFORM_PACKSWAP;
    if (mask & (1<<4)) transforms |= PNG_TRANSFORM_EXPAND;
    if (mask & (1<<5)) transforms |= PNG_TRANSFORM_INVERT_MONO;
    if (mask & (1<<6)) transforms |= PNG_TRANSFORM_SHIFT;
    if (mask & (1<<7)) transforms |= PNG_TRANSFORM_BGR;
    if (mask & (1<<8)) transforms |= PNG_TRANSFORM_SWAP_ALPHA;
    if (mask & (1<<9)) transforms |= PNG_TRANSFORM_INVERT_ALPHA;
    if (mask & (1<<10))transforms |= PNG_TRANSFORM_SWAP_ENDIAN;

    // This will now safely longjmp back here on any libpng error
    png_write_png(png_ptr, info_ptr, transforms, nullptr);
    png_destroy_write_struct(&png_ptr, &info_ptr);
    return 0;
}



