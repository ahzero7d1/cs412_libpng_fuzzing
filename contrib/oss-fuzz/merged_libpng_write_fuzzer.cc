// merged_libpng_write_fuzzer

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <vector>
#include <setjmp.h>
#include <new>
#include <algorithm>  // For std::min

#include "png.h"

static int run_first_harness(const uint8_t* data, size_t size); //iman's
static int run_second_harness(const uint8_t* data, size_t size); //nadine's 

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Run first write‐path harness
    run_first_harness(data, size);
    // Then run second write‐path harness
    run_second_harness(data, size);
    return 0;
}

// First harness dependencies
// Define a context struct to hold necessary information for the fuzzer
struct FuzzerWriteContext {
    png_structp png_ptr = nullptr;
    png_infop info_ptr = nullptr;
    std::vector<uint8_t> output_buffer; // Buffer to write PNG data into
    jmp_buf jmpbuf;
    // For libpng error handling
    // Add members for derived PNG parameters and ancillary data buffers
    uint32_t width = 0;
    uint32_t height = 0;
    int bit_depth = 0;
    int color_type = -1;
    int interlace_type = -1;
    std::vector<char*> text_keys; // Pointers to dynamically allocated text keys
    std::vector<char*> text_strings; // Pointers to dynamically allocated text strings
    std::vector<png_text> png_text_chunks; // libpng text structs
    std::vector<png_color> palette; // For palette images
    std::vector<png_byte> transparency; // For tRNS chunk

};

// Custom error handler for libpng
void user_error_fn(png_structp png_ptr, png_const_charp error_msg) {
    FuzzerWriteContext* context = static_cast<FuzzerWriteContext*>(png_get_error_ptr(png_ptr));
    // fprintf(stderr, "libpng error: %s\n", error_msg);
    if (context) {
        longjmp(context->jmpbuf, 1); // Jump back to setjmp
    } else {
        // Cannot jump, cleanup as best as possible and abort
        if (png_ptr) {
             // In a real fuzzer, might need a more robust cleanup here
             // or rely on the fuzzer runner to handle crashes.
        }
        abort();
    }
}

// Custom warning handler (optional, but good practice)
void user_warning_fn(png_structp png_ptr, png_const_charp warning_msg) {
    // In a fuzzer, we might want to log warnings but not stop execution.
    // fprintf(stderr, "libpng warning: %s\n", warning_msg);
}

// Custom write function for libpng
void user_write_data(png_structp png_ptr, png_bytep data, png_size_t length) {
    FuzzerWriteContext* context = static_cast<FuzzerWriteContext*>(png_get_io_ptr(png_ptr));
    if (context && length > 0) {
        // Append data to the output buffer
        try {
            context->output_buffer.insert(context->output_buffer.end(), data, data + length);
        } catch (const std::bad_alloc& e) {
            // Handle potential allocation failure for large output
            fprintf(stderr, "Output buffer allocation error: %s\n", e.what());
            // Trigger libpng error to longjmp
            png_error(png_ptr, "Output buffer allocation failed");
        }
    }
}

// Custom flush function (can be empty for in-memory writing)
void user_flush_data(png_structp png_ptr) {
    // No-op for in-memory writing
}

// Limited allocator to prevent excessive memory usage during fuzzing
void* limited_malloc(png_structp, png_alloc_size_t size) {
    // Limit allocations to avoid OOM errors in the fuzzer
    // Adjust this limit based on typical image sizes and fuzzer memory limits.
    // 32MB is a starting point.
    const png_alloc_size_t MAX_FUZZ_ALLOC = 32 * 1024 * 1024;
    if (size == 0) return nullptr; // malloc(0) behavior is platform-dependent
    if (size > MAX_FUZZ_ALLOC) {
        return nullptr; // Simulate allocation failure for large requests
    }
    return malloc(size);
}

// Default free function
void default_free(png_structp, png_voidp ptr) {
    free(ptr);
}

// Helper to free dynamically allocated text strings
void free_text_buffers(FuzzerWriteContext* context) {
    for (char* key : context->text_keys) {
        free(key);
    }
    context->text_keys.clear();
    for (char* str : context->text_strings) {
        free(str);
    }
    context->text_strings.clear();
    context->png_text_chunks.clear(); // These don't own the buffers
}

static int run_first_harness(const uint8_t* data, size_t size) {
    FuzzerWriteContext context;
    if (setjmp(context.jmpbuf)) {
        if (context.png_ptr)
            png_destroy_write_struct(&context.png_ptr, &context.info_ptr);
        free_text_buffers(&context);
        return 0;
    }

    context.png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING,
                                              &context,
                                              user_error_fn,
                                              user_warning_fn);
    if (!context.png_ptr) return 0;

    context.info_ptr = png_create_info_struct(context.png_ptr);
    if (!context.info_ptr) {
        png_destroy_write_struct(&context.png_ptr, nullptr);
        return 0;
    }

    png_set_mem_fn(context.png_ptr, nullptr, limited_malloc, default_free);
    png_set_write_fn(context.png_ptr, &context, user_write_data, user_flush_data);

    const size_t MIN_INPUT_SIZE = 8;
    if (size < MIN_INPUT_SIZE) {
        png_destroy_write_struct(&context.png_ptr, &context.info_ptr);
        return 0;
    }

    size_t current_offset = 0;
    context.width  = 1 + ((data[current_offset] << 8) | data[current_offset+1]);
    current_offset += 2;
    context.height = 1 + ((data[current_offset] << 8) | data[current_offset+1]);
    current_offset += 2;

    const uint32_t MAX_FUZZ_DIM = 1024;
    if (context.width == 0 || context.height == 0 ||
        context.width > MAX_FUZZ_DIM || context.height > MAX_FUZZ_DIM) {
        png_destroy_write_struct(&context.png_ptr, &context.info_ptr);
        return 0;
    }

    if (size > current_offset) {
        switch (data[current_offset] % 5) {
            case 0: context.bit_depth = 1; break;
            case 1: context.bit_depth = 2; break;
            case 2: context.bit_depth = 4; break;
            case 3: context.bit_depth = 8; break;
            case 4: context.bit_depth = 16; break;
        }
        current_offset++;
    } else context.bit_depth = 8;

    if (size > current_offset) {
        switch (data[current_offset] % 5) {
            case 0: context.color_type = PNG_COLOR_TYPE_GRAY;       break;
            case 1: context.color_type = PNG_COLOR_TYPE_GRAY_ALPHA; break;
            case 2: context.color_type = PNG_COLOR_TYPE_RGB;        break;
            case 3: context.color_type = PNG_COLOR_TYPE_RGB_ALPHA;  break;
            case 4: context.color_type = PNG_COLOR_TYPE_PALETTE;    break;
        }
        current_offset++;
    } else context.color_type = PNG_COLOR_TYPE_RGB;

    // Adjust incompatible combinations
    if ((context.color_type == PNG_COLOR_TYPE_GRAY ||
         context.color_type == PNG_COLOR_TYPE_GRAY_ALPHA) &&
        (context.bit_depth != 1 && context.bit_depth != 2 &&
         context.bit_depth != 4 && context.bit_depth != 8 &&
         context.bit_depth != 16)) {
        context.bit_depth = 8;
    }
    if (context.color_type == PNG_COLOR_TYPE_GRAY_ALPHA && context.bit_depth < 8) {
        context.color_type = PNG_COLOR_TYPE_GRAY;
    }
    if ((context.color_type == PNG_COLOR_TYPE_RGB ||
         context.color_type == PNG_COLOR_TYPE_RGB_ALPHA) &&
        (context.bit_depth != 8 && context.bit_depth != 16)) {
        context.bit_depth = 8;
    }
    if (context.color_type == PNG_COLOR_TYPE_PALETTE &&
        (context.bit_depth != 1 && context.bit_depth != 2 &&
         context.bit_depth != 4 && context.bit_depth != 8)) {
        context.bit_depth = 8;
    }

    if (size > current_offset) {
        context.interlace_type = (data[current_offset] % 2)
                                 ? PNG_INTERLACE_ADAM7
                                 : PNG_INTERLACE_NONE;
        current_offset++;
    } else context.interlace_type = PNG_INTERLACE_NONE;

    // Compression, filter, and other parameters (can be fuzzed too)
    // For simplicity, using defaults for now
    int compression_type = PNG_COMPRESSION_TYPE_BASE;
    int filter_type      = PNG_FILTER_TYPE_BASE; // Allow libpng to choose filters
    // Set the IHDR chunk
    png_set_IHDR(context.png_ptr, context.info_ptr,
                 context.width, context.height,
                 context.bit_depth, context.color_type,
                 context.interlace_type,
                 compression_type, filter_type);

    // --- Add other ancillary chunks based on fuzzer input ---
    // Use remaining fuzzer input to decide which chunks to add and their data

    // gAMA chunk
    if (size > current_offset + 2 && data[current_offset] > 127) {
        current_offset++; // Consume the flag byte
        double gamma = double((data[current_offset] << 8 |
                               data[current_offset+1])) / 100000.0;
        png_set_gAMA(context.png_ptr, context.info_ptr, gamma);
        current_offset += 2;
    } else if (size > current_offset) {
        current_offset++; // Consume the flag byte even if not used
    }

    // bKGD chunk (1 byte flag + data based on color type)
    if (size > current_offset && data[current_offset] > 127) {
        current_offset++; // Consume the flag byte
        png_color_16 background;
        memset(&background, 0, sizeof(background)); // Initialize to zero
        size_t remaining_size = size > current_offset ? size - current_offset : 0;
         if (context.color_type == PNG_COLOR_TYPE_GRAY || context.color_type == PNG_COLOR_TYPE_GRAY_ALPHA) {
            // Gray background (1 or 2 bytes)
            if (context.bit_depth <= 8 && remaining_size >= 1) {
                  background.gray = data[current_offset];
                  current_offset += 1;
            } else if (context.bit_depth == 16 && remaining_size >= 2) {
                  background.gray = (data[current_offset] << 8 | data[current_offset+1]);
                  current_offset += 2;
            }
        } else if (context.color_type == PNG_COLOR_TYPE_RGB || context.color_type == PNG_COLOR_TYPE_RGB_ALPHA) {
            // RGB background (3 or 6 bytes)
              if (context.bit_depth <= 8 && remaining_size >= 3) {
                  background.red = data[current_offset];
                  background.green = data[current_offset+1];
                  background.blue = data[current_offset+2];
                  current_offset += 3;
              } else if (context.bit_depth == 16 && remaining_size >= 6) {
                  background.red = (data[current_offset] << 8 | data[current_offset+1]);
                  background.green = (data[current_offset+2] << 8 | data[current_offset+3]);
                  background.blue = (data[current_offset+4] << 8 | data[current_offset+5]);
                  current_offset += 6;
              }
        } else if (context.color_type == PNG_COLOR_TYPE_PALETTE) {
            // Palette background (1 byte index)
            if (remaining_size >= 1) {
                  background.index = data[current_offset];
                  current_offset += 1;
            }
        }
        // Only set bKGD if we consumed some data for it
        if (current_offset > (size_t)(data + (current_offset > 0 ? -1 : 0))) { // Check if offset moved (account for flag)
              png_set_bKGD(context.png_ptr, context.info_ptr, &background);
        }

    } else if (size > current_offset) {
        current_offset++; // Consume the flag byte even if not used
    }

    // tIME chunk (1 byte flag + 7 bytes value if present)
    if (size > current_offset + 7 && data[current_offset] > 127) {
        current_offset++; // Consume the flag byte
        png_time modtime;

        // Populate modtime fields from fuzzer input (basic derivation)
        modtime.year = 1900 + (size > current_offset ? data[current_offset] : 0); // 1900 onwards
        modtime.month = 1 + (size > current_offset + 1 ? data[current_offset+1] % 12 : 0); // 1-12
        modtime.day = 1 + (size > current_offset + 2 ? data[current_offset+2] % 31 : 0);    // 1-31
        modtime.hour = size > current_offset + 3 ? data[current_offset+3] % 24 : 0;         // 0-23
        modtime.minute = size > current_offset + 4 ? data[current_offset+4] % 60 : 0;       // 0-59
        modtime.second = size > current_offset + 5 ? data[current_offset+5] % 60 : 0;       // 0-59

        // libpng requires tm struct for png_convert_from_time_t, let's use png_set_tIME directly
        // which takes png_time.
        png_set_tIME(context.png_ptr, context.info_ptr, &modtime);
        current_offset += 7;
    } else if (size > current_offset) {
        current_offset++; // Consume the flag byte even if not used
    }

    // tEXt chunks
    if (size > current_offset && data[current_offset] > 127) {
        current_offset++;
        // Fuzz multiple text chunks. The number of chunks and their content
        // are derived from the fuzzer input.
        // Let's use the next byte to determine the number of text chunks (e.g., up to 5)
        int num_text_chunks_to_fuzz = 0;
        if (size > current_offset) {
            num_text_chunks_to_fuzz = std::min((int)(data[current_offset] % 6), 5); // Max 5 chunks
            current_offset++;
        }

        context.png_text_chunks.resize(num_text_chunks_to_fuzz);

        for (int i = 0; i < num_text_chunks_to_fuzz; ++i) {
            // Each text chunk needs a key and text string
            // Use fuzzer input to determine compression and text content
            int compression_type = PNG_TEXT_COMPRESSION_NONE;
            if (size > current_offset && data[current_offset] % 2 == 1) {
                compression_type = PNG_TEXT_COMPRESSION_zTXt; // Use zTXt compression
            }
            if (size > current_offset) current_offset++; // Consume compression flag


            // Extract key and text string from fuzzer input (null-terminated)
            // Simple extraction: find the first null byte for the key, then the next for the text
            const uint8_t* key_start = data + current_offset;
            size_t key_len = 0;
            const uint8_t* key_end = (const uint8_t*)memchr(key_start, '\0', size > current_offset ? size - current_offset : 0);
            if (key_end) {
                key_len = key_end - key_start;
            } else {
                key_len = size > current_offset ? size - current_offset : 0; // Use rest if no null byte
            }

            char* key_buf = (char*)malloc(key_len + 1);
            if (!key_buf) {
                // Allocation failed, stop processing text chunks
                num_text_chunks_to_fuzz = i; // Adjust count
                break;
            }
            memcpy(key_buf, key_start, key_len);
            key_buf[key_len] = '\0';
            context.text_keys.push_back(key_buf);
            current_offset += key_len + 1; // +1 for the null terminator (or assumed null)

            const uint8_t* text_start = data + current_offset;
            size_t text_len = 0;
            const uint8_t* text_end = (const uint8_t*)memchr(text_start, '\0', size > current_offset ? size - current_offset : 0);
            if (text_end) {
                text_len = text_end - text_start;
            } else {
                text_len = size > current_offset ? size - current_offset : 0; // Use rest if no null byte
            }

            char* text_buf = (char*)malloc(text_len + 1);
              if (!text_buf) {
                  // Allocation failed, stop processing text chunks
                  num_text_chunks_to_fuzz = i; // Adjust count
                  break;
              }
            memcpy(text_buf, text_start, text_len);
            text_buf[text_len] = '\0';
            context.text_strings.push_back(text_buf);
            current_offset += text_len + 1; // +1 for the null terminator (or assumed null)


            context.png_text_chunks[i].compression = compression_type;
            context.png_text_chunks[i].key = key_buf;
            context.png_text_chunks[i].text = text_buf;
            context.png_text_chunks[i].text_length = 0; // libpng calculates this
            context.png_text_chunks[i].lang = nullptr; // Not fuzzing iTXt yet
            context.png_text_chunks[i].lang_key = nullptr; // Not fuzzing iTXt yet
        }

        if (num_text_chunks_to_fuzz > 0) {
              png_set_text(context.png_ptr, context.info_ptr, context.png_text_chunks.data(), num_text_chunks_to_fuzz);
        }
    } else if (size > current_offset) {
        current_offset++; // Consume the flag byte even if not used
    }

    // For palette images, we need to set a palette
    if (context.color_type == PNG_COLOR_TYPE_PALETTE) {

        // Allocate palette based on bit depth (up to 2^bit_depth entries)
        int num_palette_entries = 1 << context.bit_depth;
        context.palette.resize(num_palette_entries);

        // Populate palette entries from fuzzer data (if available)
        // Simple approach: fill with repeating pattern from input
        const uint8_t* palette_src = data + current_offset;
        size_t palette_src_size = size > current_offset ? size - current_offset : 0;
        size_t bytes_to_copy = std::min(palette_src_size, (size_t)num_palette_entries * 3);
        memset(context.palette.data(), 0, num_palette_entries * 3); // Initialize to black
        if (bytes_to_copy > 0) {
              memcpy(context.palette.data(), palette_src, bytes_to_copy);
        }
        current_offset += bytes_to_copy;

        png_set_PLTE(context.png_ptr, context.info_ptr, context.palette.data(), num_palette_entries);

        // Optional: Set transparency for palette entries (tRNS chunk)
        // Use next part of fuzzer data
        const uint8_t* transparency_src = data + current_offset;
        size_t transparency_src_size = size > current_offset ? size - current_offset : 0;
        int num_transparency_entries = std::min((int)transparency_src_size, num_palette_entries);

        if (num_transparency_entries > 0) {
              context.transparency.resize(num_transparency_entries);
              memcpy(context.transparency.data(), transparency_src, num_transparency_entries);
              png_set_tRNS(context.png_ptr, context.info_ptr, context.transparency.data(), num_transparency_entries, nullptr);
              current_offset += num_transparency_entries;
        }
    }


    // --- Write the header and info chunks ---
    png_write_info(context.png_ptr, context.info_ptr);

    // --- Write the pixel data ---
    size_t bytes_per_pixel = 0;
    if (context.color_type & PNG_COLOR_MASK_COLOR) { // RGB or RGB_ALPHA
        bytes_per_pixel = 3;
    } else { // Gray or Gray_ALPHA or Palette
        bytes_per_pixel = 1;
    }
    if (context.color_type & PNG_COLOR_MASK_ALPHA) { // Has Alpha
        bytes_per_pixel += 1;
    }
    // Adjust bytes per pixel for bit depths < 8
    if (context.bit_depth < 8) {
          bytes_per_pixel = 1; // Packed pixels
    } else if (context.bit_depth == 16) {
          bytes_per_pixel *= 2;
    }


    png_size_t rowbytes = png_get_rowbytes(context.png_ptr, context.info_ptr);
    // Ensure rowbytes is consistent with our calculation (libpng might add padding)
    // This isn't strictly needed but can help debug calculation mismatches
    // if (rowbytes != context.width * bytes_per_pixel && (context.bit_depth >= 8 || (context.width * context.bit_depth) % 8 != 0)) {
    //       fprintf(stderr, "Warning: Calculated rowbytes mismatch.\n");
    // }


    // Source data for pixels comes from the remaining fuzzer input
    const uint8_t* pixel_src = data + current_offset;
    size_t pixel_src_size = size > current_offset ? size - current_offset : 0;

    if (context.interlace_type == PNG_INTERLACE_ADAM7) {
        // Interlaced: Need all pixel data at once for png_write_image
        // This can require significant memory. Limit height/width accordingly.
        size_t total_pixel_data_size = context.height * rowbytes;
        if (total_pixel_data_size > 0) {
              std::vector<uint8_t> pixel_data(total_pixel_data_size);

              // Populate pixel data from fuzzer input (repeating pattern)
              if (pixel_src_size > 0) {
                 size_t bytes_to_fill = std::min(total_pixel_data_size, pixel_src_size);
                 memcpy(pixel_data.data(), pixel_src, bytes_to_fill);

                 // If not enough fuzzer data, repeat or fill with default
                 if (total_pixel_data_size > pixel_src_size) {
                    // Simple repetition or fill with 0
                      memset(pixel_data.data() + pixel_src_size, 0, total_pixel_data_size - pixel_src_size);
                 }

              } else {
                  // No fuzzer data for pixels, fill with default (black)
                  memset(pixel_data.data(), 0, total_pixel_data_size);
              }

              std::vector<png_bytep> row_pointers(context.height);
              for (png_uint_32 i = 0; i < context.height; ++i) {
                  row_pointers[i] = pixel_data.data() + i * rowbytes;
              }
              png_write_image(context.png_ptr, row_pointers.data());
        }

    } else {
        // Non-interlaced: Write row by row
        if (context.height > 0) {
            std::vector<uint8_t> row_buffer(rowbytes); // Buffer for one row

            for (png_uint_32 y = 0; y < context.height; ++y) {
                // Populate row buffer from fuzzer input (repeating pattern)
                size_t bytes_to_fill = std::min(rowbytes, pixel_src_size > 0 ? pixel_src_size : 0);
                  memset(row_buffer.data(), 0, rowbytes); // Initialize row buffer
                  if (bytes_to_fill > 0) {
                      memcpy(row_buffer.data(), pixel_src, bytes_to_fill);
                      // If not enough fuzzer data for the row, repeat or fill with default
                      if (rowbytes > pixel_src_size) {
                          memset(row_buffer.data() + pixel_src_size, 0, rowbytes - pixel_src_size);
                      }
                  } else {
                      // No fuzzer data source, fill row with default (black)
                       memset(row_buffer.data(), 0, rowbytes);
                  }

                // Note: For simplicity, this uses the *same* pixel_src for every row.
                // A more advanced fuzzer might use different parts of the input for different rows.
                // The current_offset is NOT advanced here, so each row uses the same fuzzer data chunk.

                png_write_row(context.png_ptr, row_buffer.data());
            }
        }
    }


    // --- End the PNG writing process ---
    png_write_end(context.png_ptr, context.info_ptr);

    // --- Cleanup ---
    png_destroy_write_struct(&context.png_ptr, &context.info_ptr);

    // Free dynamically allocated memory for text chunks
    free_text_buffers(&context);

    return 0; // Return 0 on success
}
// second harness dependencies
struct WriteBuffer {
    std::vector<uint8_t> data;
};

struct PngObjectHandler {
    png_infop info_ptr    = nullptr;
    png_structp png_ptr   = nullptr;
    png_infop end_info_ptr = nullptr;
    png_voidp row_ptr     = nullptr;
    WriteBuffer* write_buf = nullptr;
    ~PngObjectHandler() {
        if (row_ptr)                 png_free(png_ptr, row_ptr);
        if (info_ptr)                png_destroy_write_struct(&png_ptr, &info_ptr);
        else                         png_destroy_write_struct(&png_ptr, nullptr);
        delete write_buf;
    }
};

#define PNG_CLEANUP \
  if (png_handler.png_ptr) { \
    if (png_handler.row_ptr) \
      png_free(png_handler.png_ptr, png_handler.row_ptr); \
    if (png_handler.end_info_ptr) \
      png_destroy_write_struct(&png_handler.png_ptr, &png_handler.info_ptr); \
    else if (png_handler.info_ptr) \
      png_destroy_write_struct(&png_handler.png_ptr, &png_handler.info_ptr); \
    else \
      png_destroy_write_struct(&png_handler.png_ptr, nullptr); \
    png_handler.png_ptr    = nullptr; \
    png_handler.row_ptr    = nullptr; \
    png_handler.info_ptr   = nullptr; \
    png_handler.end_info_ptr = nullptr; \
  }

void second_user_write_data(png_structp png_ptr, png_bytep data, png_size_t length) {
    WriteBuffer* buf = static_cast<WriteBuffer*>(png_get_io_ptr(png_ptr));
    buf->data.insert(buf->data.end(), data, data + length);
}

void second_user_flush_data(png_structp) {
    // no-op
}

static int run_second_harness(const uint8_t* data, size_t size) {
    if (size < 32) return 0;
    uint32_t width  = (data[0] << 8) | data[1];
    uint32_t height = (data[2] << 8) | data[3];
    if (width == 0 || height == 0 || width > 1024 || height > 1024) return 0;
    int color_type    = data[4] % 6;
    int interlace_type= data[5] % 2;
    int filter_method = data[6] % 2;
    int bit_depth_options[] = {1,2,4,8};
    int bit_depth     = bit_depth_options[data[8] % 4];
    int compression_level = data[7] % 10;

    PngObjectHandler png_handler;
    png_handler.write_buf = new WriteBuffer();

    png_handler.png_ptr = png_create_write_struct(
      PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr
    );
    if (!png_handler.png_ptr) return 0;

    png_handler.info_ptr = png_create_info_struct(png_handler.png_ptr);
    if (!png_handler.info_ptr) {
        PNG_CLEANUP
        return 0;
    }
    if (setjmp(png_jmpbuf(png_handler.png_ptr))) {
        PNG_CLEANUP
        return 0;
    }

    png_set_write_fn(
      png_handler.png_ptr,
      png_handler.write_buf,
      second_user_write_data,
      second_user_flush_data
    );

    png_set_IHDR(
      png_handler.png_ptr,
      png_handler.info_ptr,
      width, height,
      bit_depth, color_type,
      interlace_type,
      PNG_COMPRESSION_TYPE_BASE,
      filter_method
    );

    png_set_compression_level(png_handler.png_ptr, compression_level);
    png_set_filter(png_handler.png_ptr, PNG_FILTER_TYPE_BASE, PNG_ALL_FILTERS);

    if (color_type == PNG_COLOR_TYPE_RGB ||
        color_type == PNG_COLOR_TYPE_RGBA)
      png_set_bgr(png_handler.png_ptr);
    if (color_type == PNG_COLOR_TYPE_RGB ||
        color_type == PNG_COLOR_TYPE_GRAY)
      png_set_swap(png_handler.png_ptr);
    if (bit_depth < 8)
      png_set_packing(png_handler.png_ptr);

    png_color_8 sig_bit = {
      (png_byte)bit_depth,
      (png_byte)bit_depth,
      (png_byte)bit_depth,
      (png_byte)bit_depth,
      (png_byte)bit_depth
    };
    png_set_shift(png_handler.png_ptr, &sig_bit);

    png_set_write_user_transform_fn(
      png_handler.png_ptr,
      [](png_structp, png_row_infop row_info, png_bytep row) {
        for (size_t i = 0; i < row_info->rowbytes; ++i)
          row[i] ^= 0xFF;
      }
    );

    png_text text_ptr[2];
    text_ptr[0].compression = PNG_TEXT_COMPRESSION_NONE;
    text_ptr[0].key         = (char*)"Comment";
    text_ptr[0].text        = (char*)"Generated by fuzzer";

    char fuzz_buf[32] = {0};
    memcpy(fuzz_buf, &data[10], std::min(size-10, sizeof(fuzz_buf)-1));
    text_ptr[1].compression = PNG_TEXT_COMPRESSION_NONE;
    text_ptr[1].key         = (char*)"FuzzKey";
    text_ptr[1].text        = fuzz_buf;
    png_set_text(png_handler.png_ptr, png_handler.info_ptr, text_ptr, 2);

    png_time png_time_now = {2025, 5, 13, 12, 34, 56};
    png_set_tIME(png_handler.png_ptr, png_handler.info_ptr, &png_time_now);

    if (color_type == PNG_COLOR_TYPE_PALETTE) {
      png_color palette[2] = {{255,0,0},{0,255,0}};
      png_set_PLTE(png_handler.png_ptr, png_handler.info_ptr, palette, 2);
    }

#ifdef PNG_WRITE_UNKNOWN_CHUNKS_SUPPORTED
    png_unknown_chunk unk;
    memcpy(unk.name, "abcd", 4);
    unk.data     = const_cast<png_byte*>(&data[20]);
    unk.size     = std::min<size_t>(size-20, 8);
    unk.location = PNG_HAVE_IHDR;
    png_set_unknown_chunks(png_handler.png_ptr, png_handler.info_ptr, &unk, 1);
    png_set_unknown_chunk_location(png_handler.png_ptr, png_handler.info_ptr, 0, PNG_HAVE_IHDR);
#endif

    int passes = png_set_interlace_handling(png_handler.png_ptr);
    png_write_info(png_handler.png_ptr, png_handler.info_ptr);

    {
      size_t rowbytes = png_get_rowbytes(png_handler.png_ptr, png_handler.info_ptr);
      std::vector<uint8_t> image_data(rowbytes * height, 0);
      std::vector<png_bytep> row_ptrs(height);
      for (size_t i = 0; i < height; ++i)
        row_ptrs[i] = image_data.data() + i * rowbytes;
      for (int p = 0; p < passes; ++p)
        png_write_rows(png_handler.png_ptr, row_ptrs.data(), height);
    }

    png_write_end(png_handler.png_ptr, nullptr);
    PNG_CLEANUP
    return 0;
}


