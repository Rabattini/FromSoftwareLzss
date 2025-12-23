This was made for working with **FromSoftware PlayStation 2 (PS2) games** that use this `fsliblzs` container + STRETCH-compressed payloads.

---

## Features

- Decompresses `.STRETCH` → raw `.bin`
- **Windows drag & drop support**
  - Drop a `.STRETCH` file onto the `.exe` and it will create `input.bin` automatically
- Standard CLI mode with explicit output path
- Optional `base` argument (defaults to `0x20`)

---

## Usage

### Windows (Drag & Drop)
1. Build the executable
2. Drag a `.STRETCH` file onto `stretch_decomp_fun001aa220.exe`
3. Output will be created next to the input as:
   - `input.bin` (extension replaced with `.bin`)

### Command line
```bash
stretch_decomp_fun001aa220 <input.STRETCH> <output.bin>
