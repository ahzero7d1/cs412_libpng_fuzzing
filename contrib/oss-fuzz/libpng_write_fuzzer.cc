// libpng_write_fuzzer.cc
// Based on libpng documentation and libpng_read_fuzzer.cc structure.

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <setjmp.h> // Required for libpng error handling

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

// Structure to hold libpng pointers and manage cleanup
struct PngObjectHandler {
  png_structp png_ptr = nullptr;
  png_infop info_ptr = nullptr;

  ~PngObjectHandler() {
    if (png_ptr) {
      // Use png_destroy_write_struct for cleanup
      png_destroy_write_struct(&png_ptr, &info_ptr);
    }
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

  // Use custom memory allocator
  png_set_mem_fn(png_handler.png_ptr, nullptr, limited_malloc, default_free);

  // Set up custom write function
  png_set_write_fn(png_handler.png_ptr, nullptr, user_write_data, user_flush_data);

  // --- Determine PNG parameters from fuzzer input ---
  // Use first few bytes for parameters. Be careful with values.
  uint32_t width = 1;
  uint32_t height = 1;
  int bit_depth = 8;
  int color_type = PNG_COLOR_TYPE_RGB; // Default to RGB
  int interlace_method = PNG_INTERLACE_NONE;

  // Read parameters from input buffer defensively
  if (size >= 4) width = *(uint32_t*)data;
  if (size >= 8) height = *(uint32_t*)(data + 4);
  if (size >= 9) bit_depth = (data[8] % 2 == 0) ? 8 : 16; // Simple bit depth choice
  if (size >= 10) {
    uint8_t type = data[9] % 5; // 5 possible color types
    switch (type) {
      case 0: color_type = PNG_COLOR_TYPE_GRAY; break;
      case 1: color_type = PNG_COLOR_TYPE_PALETTE; break; // Requires palette
      case 2: color_type = PNG_COLOR_TYPE_RGB; break;
      case 3: color_type = PNG_COLOR_TYPE_RGB_ALPHA; break;
      case 4: color_type = PNG_COLOR_TYPE_GRAY_ALPHA; break;
    }
  }
   if (size >= 11) {
    interlace_method = (data[10] % 2 == 0) ? PNG_INTERLACE_NONE : PNG_INTERLACE_ADAM7;
  }

  // Sanitize dimensions to prevent excessive memory allocation
  // Max total pixels to prevent OOM, adjust as needed
  const uint64_t MAX_PIXELS = 1000000; // 1 Megapixel limit
  if (width == 0 || height == 0 || (uint64_t)width * height > MAX_PIXELS) {
      // Use a small default valid image if dimensions are problematic
      width = 10;
      height = 10;
      bit_depth = 8;
      color_type = PNG_COLOR_TYPE_RGB;
      interlace_method = PNG_INTERLACE_NONE;
  }

  // Further sanitize bit depth based on color type
  if (color_type == PNG_COLOR_TYPE_PALETTE) {
      if (bit_depth != 1 && bit_depth != 2 && bit_depth != 4 && bit_depth != 8) bit_depth = 8;
  } else if (color_type == PNG_COLOR_TYPE_GRAY || color_type == PNG_COLOR_TYPE_GRAY_ALPHA) {
      if (bit_depth != 1 && bit_depth != 2 && bit_depth != 4 && bit_depth != 8 && bit_depth != 16) bit_depth = 8;
  } else { // RGB or RGBA
       if (bit_depth != 8 && bit_depth != 16) bit_depth = 8;
  }

  // Set image header information
  png_set_IHDR(png_handler.png_ptr, png_handler.info_ptr, width, height,
               bit_depth, color_type, interlace_method,
               PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);

  // --- Set Optional Information (driven by input) ---

  // Gamma (use part of input data)
  if (size > 12 && data[11] > 0) { // Use byte 12 as a flag and value
      double gamma = (double)data[12] / 100.0; // Simple mapping
      if (gamma > 0.0) {
          png_set_gAMA(png_handler.png_ptr, png_handler.info_ptr, gamma);
      }
  }

  // Time (use part of input data)
  if (size > 14 && data[13] > 0) { // Use byte 14 as a flag
      png_time modtime;
    //   png_convert_from_time_t(&modtime, time(NULL)); // Use current time
      png_set_tIME(png_handler.png_ptr, png_handler.info_ptr, &modtime);
  }

  // Background color (use part of input data)
   if (size > 18 && data[15] > 0 &&
       (color_type == PNG_COLOR_TYPE_RGB_ALPHA || color_type == PNG_COLOR_TYPE_GRAY_ALPHA || color_type == PNG_COLOR_TYPE_PALETTE) ) { // Only applicable to alpha or paletted
       png_color_16 background;
       background.red = data[16] * 257; // Scale 8-bit to 16-bit
       background.green = data[17] * 257;
       background.blue = data[18] * 257;
       // For grayscale, only set gray component
       if (color_type == PNG_COLOR_TYPE_GRAY_ALPHA) background.gray = data[16]; // Or map from one channel
       png_set_bKGD(png_handler.png_ptr, png_handler.info_ptr, &background);
   }

  // Text chunks (simple example: one text chunk if enough data)
   if (size > 20 && data[19] > 0) { // Use byte 20 as a flag
       // Use remaining data for text, up to a limit
       const char* text_key = "Comment";
       // Ensure there's enough data for at least a short text string
       if (size > 20) {
            std::vector<png_text> text_chunks;
            png_text text_chunk;
            text_chunk.compression = PNG_TEXT_COMPRESSION_NONE; // No compression
            text_chunk.key = (png_charp)text_key;
            // Use a portion of the input data as the text string
            size_t text_len = std::min((size_t)(data[20] % 100 + 1), size - 21); // Length from input, max 100 + 1
            if (text_len > 0) {
                std::string text_string((const char*)data + 21, text_len);
                text_chunk.text = (png_charp)text_string.c_str();
                text_chunk.text_length = text_len;
                text_chunks.push_back(text_chunk);
                png_set_text(png_handler.png_ptr, png_handler.info_ptr, text_chunks.data(), text_chunks.size());
            }
       }
   }


  // --- Write Header ---
  png_write_info(png_handler.png_ptr, png_handler.info_ptr);

  // --- Write Image Data ---
  png_size_t rowbytes = png_get_rowbytes(png_handler.png_ptr, png_handler.info_ptr);
  std::vector<png_byte> row_data(rowbytes);

  // Use remaining fuzzer input to populate pixel data
  size_t data_offset = 21 + (size > 20 ? (data[20] % 100 + 1) : 0); // Offset past params and potential text length byte

  for (png_uint_32 y = 0; y < height; ++y) {
    // Fill row_data using input data, repeating if necessary
    size_t bytes_to_copy = std::min((size_t)rowbytes, size > data_offset ? size - data_offset : 0);
    if (bytes_to_copy > 0) {
        memcpy(row_data.data(), data + data_offset, bytes_to_copy);
        // If row data is larger than available input, repeat or fill with zeros
        if (bytes_to_copy < rowbytes) {
            // Simple repetition for the rest of the row
            size_t copied = bytes_to_copy;
            while(copied < rowbytes) {
                size_t to_repeat = std::min((size_t)rowbytes - copied, bytes_to_copy);
                memcpy(row_data.data() + copied, row_data.data(), to_repeat);
                copied += to_repeat;
            }
        }
    } else {
        // No more input data, fill with zeros
        memset(row_data.data(), 0, rowbytes);
    }

    png_write_row(png_handler.png_ptr, row_data.data());
  }

  // --- Write End of File ---
  png_write_end(png_handler.png_ptr, png_handler.info_ptr);

  // PngObjectHandler destructor handles cleanup

  return 0;
}