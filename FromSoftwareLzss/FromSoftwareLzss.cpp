//
// Usage:
//   tool.exe <input.STRETCH> [output.bin] [base]
//   tool.exe <input1> <input2> ... [base]
//
// Drag & Drop (Windows Explorer):
//   - Drop one file:  tool.exe <input>  => outputs <input>.bin
//   - Drop many:      tool.exe <in1> <in2> ... => outputs <in1>.bin, <in2>.bin, ...
//
// Notes (core logic):
// - Expects "fsliblzs" at file start.
// - Reads expected compressed size at offset 0x10 (LE u32).
// - Reads expected compressed size at offset 0x24 (BE u32).
// - Decompression logic:
//     flags at base+0x0C, stream at base+0x0D
//     LSB-first bits, bit=0 literal, bit=1 backref
//     backref: offset=(b0<<4)+(b1>>4), len=(b1&0x0F)+1, if (b1&0x0F)==0 => end
//     sliding 0x1000 window via moving base pointer (window_base)
//


#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

static uint32_t read_u32_le(const std::vector<uint8_t>& b, size_t off) {
    if (off + 4 > b.size()) throw std::runtime_error("read_u32_le out of range");
    return (uint32_t)b[off] |
        ((uint32_t)b[off + 1] << 8) |
        ((uint32_t)b[off + 2] << 16) |
        ((uint32_t)b[off + 3] << 24);
}

static uint32_t read_u32_be(const std::vector<uint8_t>& b, size_t off) {
    if (off + 4 > b.size()) throw std::runtime_error("read_u32_be out of range");
    return ((uint32_t)b[off] << 24) |
        ((uint32_t)b[off + 1] << 16) |
        ((uint32_t)b[off + 2] << 8) |
        (uint32_t)b[off + 3];
}

static std::vector<uint8_t> read_all(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Failed to open input: " + path);
    f.seekg(0, std::ios::end);
    std::streamoff sz = f.tellg();
    f.seekg(0, std::ios::beg);
    if (sz < 0) throw std::runtime_error("Invalid file size.");
    std::vector<uint8_t> data((size_t)sz);
    if (!data.empty()) f.read(reinterpret_cast<char*>(data.data()), sz);
    return data;
}

static void write_all(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Failed to open output: " + path);
    if (!data.empty()) f.write(reinterpret_cast<const char*>(data.data()),
        (std::streamsize)data.size());
}

static int parse_int_auto(const std::string& s) {
    // accepts 0x.. or decimal
    size_t idx = 0;
    int base = 10;
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) base = 16;
    long v = std::stol(s, &idx, base);
    if (idx != s.size()) throw std::runtime_error("Invalid integer: " + s);
    return (int)v;
}

static std::vector<uint8_t> fslzss_decompress(const std::vector<uint8_t>& blob, size_t base, uint32_t expected) {
    if (base + 0x0D > blob.size()) throw std::runtime_error("base out of range.");

    // raw copy branch
    if (blob[base + 0x0B] == 0x01) {
        uint32_t size_be = read_u32_be(blob, base + 4);
        size_t start = base + 0x0C;
        size_t end = start + size_be;
        if (start > blob.size()) throw std::runtime_error("raw branch start out of range.");
        if (end > blob.size()) end = blob.size();
        std::vector<uint8_t> out(blob.begin() + (std::ptrdiff_t)start,
            blob.begin() + (std::ptrdiff_t)end);
        if (out.size() > expected) out.resize(expected);
        return out;
    }

    uint8_t flags = blob[base + 0x0C];
    size_t i = base + 0x0D;
    uint16_t mask = 1;

    std::vector<uint8_t> out;
    out.reserve(expected);

    size_t window_base = 0;
    bool first_align = true;

    auto maybe_slide = [&](size_t u) {
        if ((out.size() - window_base) > 0x0FFF) {
            window_base += u;
            if (first_align) {
                if (out.size() >= 0x1000) window_base = out.size() - 0x1000;
                else window_base = 0;
                first_align = false;
            }
        }
        };

    while (i < blob.size() && out.size() < expected) {
        bool backref = (flags & (uint8_t)mask) != 0; // 0 literal, 1 backref

        size_t u = 0;
        if (!backref) {
            // literal
            out.push_back(blob[i]);
            i += 1;
            u = 1;
        }
        else {
            // backref
            if (i + 1 >= blob.size()) break;
            uint8_t b0 = blob[i];
            uint8_t b1 = blob[i + 1];
            i += 2;

            uint32_t offset = ((uint32_t)b0 << 4) + ((uint32_t)b1 >> 4);
            uint32_t ln = (uint32_t)(b1 & 0x0F);
            if (ln == 0) break;
            u = (size_t)(ln + 1);

            size_t src = window_base + (size_t)offset;
            for (size_t k = 0; k < u && out.size() < expected; ++k) {
                size_t idx = src + k;
                if (idx >= out.size()) {
                    throw std::runtime_error("Bad backref: idx >= out.size() (overlap/read-before-write mismatch).");
                }
                out.push_back(out[idx]);
            }
        }

        maybe_slide(u);

        mask <<= 1;
        if (mask == 0x100) {
            if (i >= blob.size()) break;
            flags = blob[i];
            i += 1;
            mask = 1;
        }
    }

    return out;
}

// ---------- Drag & drop / convenience helpers ----------
static bool looks_like_int(const std::string& s) {
    try {
        (void)parse_int_auto(s);
        return true;
    }
    catch (...) {
        return false;
    }
}

static std::string default_out_path_for(const std::string& in_path) {
    namespace fs = std::filesystem;
    fs::path p(in_path);
    p.replace_extension(".bin");
    return p.string();
}

static bool path_exists(const std::string& p) {
    namespace fs = std::filesystem;
    try {
        return fs::exists(fs::path(p));
    }
    catch (...) {
        return false;
    }
}

static void print_usage() {
    std::cerr << "Lzss Decompressor From Software - made by Rabatini (Luke)\nUsage:\n";
    std::cerr << "  tool.exe <input.STRETCH> [output.bin] [base]\n";
    std::cerr << "  tool.exe <input1> <input2> ... [base]\n\n";
    std::cerr << "base: hex (0x..) or decimal, default 0x20\n";
    std::cerr << "Drag&Drop:\n";
    std::cerr << "  - Drop 1 file => output <input>.bin\n";
    std::cerr << "  - Drop many   => outputs <in>.bin for each\n";
}

int main(int argc, char** argv) {
    try {
        if (argc < 2 || argc > 4) {
            std::cerr << "Lzss Decompressor FromSoftware - made by Rabatini (Luke)\n";
            std::cerr << "Usage: tool.exe <input.STRETCH> <output.bin> [base]\n";
            std::cerr << "Drag&drop: tool.exe <input.STRETCH>  (gera <input>.bin)\n";
            
            return 2;
        }

        std::string in_path = argv[1];

        // Drag&drop: se veio só input, gera output automático trocando extensão por .bin
        std::string out_path;
        if (argc == 2) {
            namespace fs = std::filesystem;
            fs::path p(in_path);
            p.replace_extension(".bin");
            out_path = p.string();
        }
        else {
            out_path = argv[2];
        }

        size_t base = 0x20;
        if (argc == 4) {
            base = (size_t)parse_int_auto(argv[3]);
        }

        std::vector<uint8_t> data = read_all(in_path);
        if (data.size() < 0x28) throw std::runtime_error("File too small.");

        const char magic[] = "fsliblzs";
        if (std::memcmp(data.data(), magic, 8) != 0) {
            throw std::runtime_error("Not a fsliblzs container (missing 'fsliblzs' magic).");
        }

        // 0x10 = compressed size (LE)  |  0x24 = decompressed size (BE)
        uint32_t compressed_sz = read_u32_le(data, 0x10);
        uint32_t expected = read_u32_be(data, 0x24);

        // fallback (caso algum arquivo não use 0x24)
        if (expected == 0) expected = compressed_sz;

        std::vector<uint8_t> out = fslzss_decompress(data, base, expected);

        // Se você quiser checar tamanho exato:
        // if (out.size() != expected) throw std::runtime_error("Output size mismatch.");

        write_all(out_path, out);
        std::cout << "OK: wrote " << out.size() << " bytes to " << out_path << "\n";
        std::cout << "expected (0x24 BE): " << expected << "\n";
        std::cout << "compressed (0x10 LE): " << compressed_sz << "\n";
        std::cout << "base: 0x" << std::hex << base << std::dec << "\n";
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << "\n";
        return 1;
    }
}
