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

void custom_flush(png_structp) {
    // No-op
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 40) return 0;  // need at least 40 bytes

    png_structp png_ptr = nullptr;
    png_infop   info_ptr = nullptr;
    jmp_buf     jmpbuf;
    WriteBuffer out_buffer;

    do {
        // 1) create structs
        png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, &jmpbuf, nullptr, nullptr);
        if (!png_ptr) break;
        info_ptr = png_create_info_struct(png_ptr);
        if (!info_ptr) { png_destroy_write_struct(&png_ptr, nullptr); break; }
        if (setjmp(jmpbuf)) {
            png_destroy_write_struct(&png_ptr, &info_ptr);
            break;
        }
        png_set_write_fn(png_ptr, &out_buffer, custom_write, custom_flush);

        // 2) parse IHDR from first 7 bytes
        uint32_t width  = 1 + ((data[0] << 8) | data[1])  % 256;
        uint32_t height = 1 + ((data[2] << 8) | data[3])  % 256;
        static const int ct_choices[] = {
            PNG_COLOR_TYPE_GRAY,
            PNG_COLOR_TYPE_GRAY_ALPHA,
            PNG_COLOR_TYPE_RGB,
            PNG_COLOR_TYPE_RGB_ALPHA
        };
        int color_type = ct_choices[data[4] % 4];
        static const int bd_choices[] = {1,2,4,8,16};
        int bit_depth = bd_choices[data[5] % 5];
        int interlace = data[6] % 2;

        // skip invalid combos
        if ((color_type == PNG_COLOR_TYPE_GRAY       && !(bit_depth==1||bit_depth==2||bit_depth==4||bit_depth==8||bit_depth==16)) ||
            (color_type == PNG_COLOR_TYPE_GRAY_ALPHA && !(bit_depth==8||bit_depth==16)) ||
            (color_type == PNG_COLOR_TYPE_RGB        && !(bit_depth==8||bit_depth==16)) ||
            (color_type == PNG_COLOR_TYPE_RGB_ALPHA  && !(bit_depth==8||bit_depth==16)))
            break;

        png_set_IHDR(png_ptr, info_ptr,
                     width, height, bit_depth,
                     color_type, interlace,
                     PNG_COMPRESSION_TYPE_BASE,
                     PNG_FILTER_TYPE_BASE);

        // 3) allocate and fill pixel buffer
        png_size_t rowbytes = png_get_rowbytes(png_ptr, info_ptr);
        const size_t MAX_PIXELS = 16u<<20; // 16 MiB
        if (rowbytes == 0 || rowbytes * height > MAX_PIXELS) break;
        std::vector<uint8_t> image_data(rowbytes * height, 0);
        if (size > 40) {
            memcpy(image_data.data(),
                   data + 40,
                   std::min(image_data.size(), size - 40));
        }
        std::vector<png_bytep> rows(height);
        for (uint32_t y = 0; y < height; ++y)
            rows[y] = image_data.data() + (size_t)y * rowbytes;
        png_set_rows(png_ptr, info_ptr, rows.data());

        // 4) extract transforms from bytes [36..39]
        uint32_t val = ((uint32_t)data[36] << 24)
                     | ((uint32_t)data[37] << 16)
                     | ((uint32_t)data[38] <<  8)
                     |  (uint32_t)data[39];
        int transforms = 0;
        if (val & (1u<<0))  transforms |= PNG_TRANSFORM_STRIP_16;
        if (val & (1u<<1))  transforms |= PNG_TRANSFORM_STRIP_ALPHA;
        if (val & (1u<<2))  transforms |= PNG_TRANSFORM_PACKING;
        if (val & (1u<<3))  transforms |= PNG_TRANSFORM_PACKSWAP;
        if (val & (1u<<4))  transforms |= PNG_TRANSFORM_EXPAND;
        if (val & (1u<<5))  transforms |= PNG_TRANSFORM_INVERT_MONO;
        if (val & (1u<<6))  transforms |= PNG_TRANSFORM_SHIFT;
        if (val & (1u<<7))  transforms |= PNG_TRANSFORM_BGR;
        if (val & (1u<<8))  transforms |= PNG_TRANSFORM_SWAP_ALPHA;
        if (val & (1u<<9))  transforms |= PNG_TRANSFORM_INVERT_ALPHA;
        if (val & (1u<<10)) transforms |= PNG_TRANSFORM_SWAP_ENDIAN;

        // 5) finally hit the high‐level API
        png_write_png(png_ptr, info_ptr, transforms, nullptr);

    } while (0);

    png_destroy_write_struct(&png_ptr, &info_ptr);
    return 0;
}






