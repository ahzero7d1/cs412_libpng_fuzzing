#include <stdint.h>
#include <stddef.h>
#include <vector>
#include <string.h>
#include <png.h>
#include <setjmp.h>

// --- In-memory write buffer ---
struct WriteBuffer {
    std::vector<uint8_t> data;
};

// Write callback
void custom_write(png_structp png_ptr, png_bytep data, png_size_t length) {
    auto* buf = static_cast<WriteBuffer*>(png_get_io_ptr(png_ptr));
    buf->data.insert(buf->data.end(), data, data + length);
}
void custom_flush(png_structp) { /* no-op */ }

// Error handler: on any png_error(), jump back to setjmp
void user_error_fn(png_structp png_ptr, png_const_charp msg) {
    jmp_buf* jb = static_cast<jmp_buf*>(png_get_error_ptr(png_ptr));
    longjmp(*jb, 1);
}
// Warnings are ignored
void user_warning_fn(png_structp, png_const_charp) {}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 40) return 0;  // we need at least 40 bytes

    jmp_buf jb;
    // Create png_struct with our error/warning handlers
    png_structp png_ptr = png_create_write_struct(
        PNG_LIBPNG_VER_STRING,
        &jb,               // this ptr passed to user_error_fn
        user_error_fn,
        user_warning_fn
    );
    if (!png_ptr) return 0;

    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_write_struct(&png_ptr, nullptr);
        return 0;
    }

    // Catch all png_error() calls here
    if (setjmp(jb)) {
        png_destroy_write_struct(&png_ptr, &info_ptr);
        return 0;
    }

    // Install our write callbacks
    WriteBuffer out;
    png_set_write_fn(png_ptr, &out, custom_write, custom_flush);

    // --- Parse IHDR from fuzz data ---
    // Force small dims so we don't allocate millions of bytes
    uint32_t W = 1 + ((data[0]<<8 | data[1]) % 128);
    uint32_t H = 1 + ((data[2]<<8 | data[3]) % 128);

    // Only these four color types (no palette)
    int types[] = {
      PNG_COLOR_TYPE_GRAY,
      PNG_COLOR_TYPE_GRAY_ALPHA,
      PNG_COLOR_TYPE_RGB,
      PNG_COLOR_TYPE_RGB_ALPHA
    };
    int ct = types[data[4] % 4];

    int depths[] = {1,2,4,8,16};
    int bd = depths[data[5] % 5];

    // Reject invalid combos
    bool bad = false;
    if ((ct & PNG_COLOR_MASK_COLOR) && bd!=8 && bd!=16) bad = true;
    if (!(ct & PNG_COLOR_MASK_COLOR) && bd!=1&&bd!=2&&bd!=4&&bd!=8&&bd!=16) bad = true;
    if (bad) {
      png_destroy_write_struct(&png_ptr,&info_ptr);
      return 0;
    }

    int interlace = data[6] % 2;
    png_set_IHDR(png_ptr, info_ptr, W, H, bd, ct,
                 interlace,
                 PNG_COMPRESSION_TYPE_BASE,
                 PNG_FILTER_TYPE_BASE);

    // Build a zero-image
    png_size_t rowbytes = png_get_rowbytes(png_ptr, info_ptr);
    const size_t MAX_PIX = 1<<24;
    if (rowbytes==0 || (size_t)rowbytes*H > MAX_PIX) {
      png_destroy_write_struct(&png_ptr,&info_ptr);
      return 0;
    }

    std::vector<uint8_t> img(rowbytes * H);
    // Seed it with the remainder of data
    if (size > 40) {
      memcpy(img.data(), data+40, std::min<size_t>(img.size(), size-40));
    }

    std::vector<png_bytep> rows(H);
    for (unsigned y=0; y<H; y++)
      rows[y] = img.data() + y*rowbytes;
    png_set_rows(png_ptr, info_ptr, rows.data());

    // Decode a 32-bit transform mask from bytes [36..39]
    uint32_t mask = (data[36]<<24)|(data[37]<<16)|(data[38]<<8)|data[39];
    int transforms = 0;
    if (mask & (1<<0)) transforms |= PNG_TRANSFORM_STRIP_16;
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

    // This now returns normally or jumps back on error:
    png_write_png(png_ptr, info_ptr, transforms, nullptr);

    png_destroy_write_struct(&png_ptr, &info_ptr);
    return 0;
}




