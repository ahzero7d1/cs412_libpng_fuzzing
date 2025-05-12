with open("crash.bin", "wb") as f:
    # Width = 999 (0x03E7)
    f.write(bytes([0x03, 0xE7]))
    # Height = 1
    f.write(bytes([0x00, 0x01]))
    # Color type = 6 (RGBA)
    f.write(bytes([0x06]))
    # Bit depth flag to get 16-bit
    f.write(bytes([0x01]))
    # Additional flags
    f.write(bytes([0x01, 0x00]))
    # Padding bytes
    f.write(bytes([0x00] * 8))
    # Fill pattern
    f.write(bytes([i % 256 for i in range(10000)]))

print("Created crash.bin - run with:")
print("./write_fuzzer crash.bin")