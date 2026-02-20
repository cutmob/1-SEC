package injection

import (
	"encoding/binary"
	"math"
	"strings"

	"github.com/1sec-project/1sec/internal/core"
)

// FileSentinel analyzes uploaded file content for structural anomalies that
// indicate exploitation attempts — polyglot files, embedded shellcode,
// malformed headers, and entropy anomalies. Pure Go, zero external deps.
//
// This addresses the gap where regex-based injection detection cannot inspect
// binary file formats (images, documents, archives) for memory corruption
// payloads like heap overflows, OOB writes, and buffer overflows commonly
// seen in ZDI advisories targeting parsers (GIMP, PDF-XChange, etc.).
type FileSentinel struct{}

// FileFinding represents a suspicious finding in an uploaded file.
type FileFinding struct {
	Type        string
	Description string
	Severity    core.Severity
}

// knownMagic maps file extensions to their expected magic bytes.
var knownMagic = map[string][]byte{
	"png":  {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
	"jpg":  {0xFF, 0xD8, 0xFF},
	"jpeg": {0xFF, 0xD8, 0xFF},
	"gif":  {0x47, 0x49, 0x46, 0x38},
	"pdf":  {0x25, 0x50, 0x44, 0x46},
	"zip":  {0x50, 0x4B, 0x03, 0x04},
	"gz":   {0x1F, 0x8B},
	"bmp":  {0x42, 0x4D},
	"tiff": {0x49, 0x49, 0x2A, 0x00}, // little-endian TIFF
	"webp": {0x52, 0x49, 0x46, 0x46}, // RIFF header
	"exe":  {0x4D, 0x5A},             // MZ header
	"elf":  {0x7F, 0x45, 0x4C, 0x46}, // ELF
	"class": {0xCA, 0xFE, 0xBA, 0xBE}, // Java class
}

// shellcodeSignatures are byte patterns commonly found in shellcode payloads.
var shellcodeSignatures = []struct {
	pattern []byte
	name    string
}{
	{[]byte{0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90}, "NOP sled (x86)"},
	{[]byte{0xCC, 0xCC, 0xCC, 0xCC}, "INT3 breakpoint sled"},
	{[]byte{0x31, 0xC0, 0x50, 0x68}, "x86 shellcode prologue (xor eax,eax; push eax; push)"},
	{[]byte{0x48, 0x31, 0xC0, 0x48, 0x31, 0xFF}, "x64 shellcode prologue (xor rax,rax; xor rdi,rdi)"},
	{[]byte{0x6A, 0x02, 0x58, 0xCD, 0x80}, "Linux syscall (fork)"},
	{[]byte{0x6A, 0x3B, 0x58, 0x99}, "Linux execve shellcode"},
	{[]byte{0x68, 0x2F, 0x2F, 0x73, 0x68}, "push '//sh' (Linux shell spawn)"},
}

// Analyze inspects raw file bytes and declared extension/content-type for anomalies.
func (fs *FileSentinel) Analyze(data []byte, declaredExt, contentType string) []FileFinding {
	if len(data) == 0 {
		return nil
	}

	var findings []FileFinding

	// 1. Magic byte mismatch — polyglot detection
	if f := fs.checkMagicMismatch(data, declaredExt, contentType); f != nil {
		findings = append(findings, *f)
	}

	// 2. Embedded executable detection
	if f := fs.checkEmbeddedExecutable(data, declaredExt); f != nil {
		findings = append(findings, *f)
	}

	// 3. Shellcode signature scan
	findings = append(findings, fs.checkShellcode(data)...)

	// 4. Entropy anomaly — high entropy in non-compressed files suggests encryption/packing
	if f := fs.checkEntropyAnomaly(data, declaredExt); f != nil {
		findings = append(findings, *f)
	}

	// 5. Oversized header fields — common in heap overflow exploits
	if f := fs.checkOversizedHeaders(data, declaredExt); f != nil {
		findings = append(findings, *f)
	}

	// 6. Archive entry path traversal — Zip Slip detection (CVE-2025-69770)
	if f := fs.checkArchiveTraversal(data, declaredExt); f != nil {
		findings = append(findings, *f)
	}

	return findings
}

// checkArchiveTraversal inspects ZIP archives for Zip Slip attacks where
// archive entries contain path traversal sequences (../) to write files
// outside the intended extraction directory. Addresses CVE-2025-69770.
func (fs *FileSentinel) checkArchiveTraversal(data []byte, declaredExt string) *FileFinding {
	ext := strings.ToLower(declaredExt)
	if ext != ".zip" && ext != ".jar" && ext != ".war" && ext != ".apk" && ext != ".epub" {
		// Only check ZIP-family archives
		if len(data) < 4 || data[0] != 0x50 || data[1] != 0x4B || data[2] != 0x03 || data[3] != 0x04 {
			return nil
		}
	}

	// Scan for local file headers in the ZIP and check filenames for traversal
	// ZIP local file header signature: PK\x03\x04
	sig := []byte{0x50, 0x4B, 0x03, 0x04}
	offset := 0
	for offset < len(data)-30 {
		idx := bytesIndex(data[offset:], sig)
		if idx < 0 {
			break
		}
		pos := offset + idx
		if pos+30 > len(data) {
			break
		}
		// Filename length is at offset 26-27 from the local header
		fnLen := int(binary.LittleEndian.Uint16(data[pos+26 : pos+28]))
		if fnLen <= 0 || pos+30+fnLen > len(data) {
			offset = pos + 4
			continue
		}
		filename := string(data[pos+30 : pos+30+fnLen])
		if strings.Contains(filename, "../") || strings.Contains(filename, "..\\") {
			return &FileFinding{
				Type:        "zip_slip_traversal",
				Description: "Archive entry contains path traversal (Zip Slip): " + filename + " — may write files outside extraction directory (ref: CVE-2025-69770)",
				Severity:    core.SeverityCritical,
			}
		}
		offset = pos + 30 + fnLen
	}
	return nil
}

// checkMagicMismatch detects polyglot files where the declared type doesn't
// match the actual file content. Attackers use this to bypass content-type
// filters (e.g., upload a PHP file disguised as a JPEG).
func (fs *FileSentinel) checkMagicMismatch(data []byte, declaredExt, contentType string) *FileFinding {
	ext := strings.ToLower(strings.TrimPrefix(declaredExt, "."))
	if ext == "" {
		return nil
	}

	expectedMagic, known := knownMagic[ext]
	if !known {
		return nil
	}

	if len(data) < len(expectedMagic) {
		return &FileFinding{
			Type:        "polyglot_truncated",
			Description: "File too small for declared type " + ext + " — possible truncated polyglot",
			Severity:    core.SeverityMedium,
		}
	}

	for i, b := range expectedMagic {
		if data[i] != b {
			// Check if it's actually an executable masquerading as an image/doc
			actualType := identifyByMagic(data)
			return &FileFinding{
				Type: "polyglot_mismatch",
				Description: "File declared as " + ext + " but magic bytes indicate " +
					actualType + " — polyglot file detected",
				Severity: core.SeverityCritical,
			}
		}
	}

	return nil
}

// checkEmbeddedExecutable looks for executable signatures embedded within
// non-executable files (e.g., MZ/ELF headers inside a PNG).
func (fs *FileSentinel) checkEmbeddedExecutable(data []byte, declaredExt string) *FileFinding {
	ext := strings.ToLower(strings.TrimPrefix(declaredExt, "."))
	// Skip if the file is supposed to be an executable
	if ext == "exe" || ext == "dll" || ext == "elf" || ext == "so" || ext == "class" || ext == "jar" {
		return nil
	}

	execMagics := []struct {
		magic []byte
		name  string
	}{
		{[]byte{0x4D, 0x5A}, "PE/MZ executable"},
		{[]byte{0x7F, 0x45, 0x4C, 0x46}, "ELF binary"},
		{[]byte{0xCA, 0xFE, 0xBA, 0xBE}, "Java class / Mach-O fat binary"},
		{[]byte{0xFE, 0xED, 0xFA, 0xCE}, "Mach-O 32-bit"},
		{[]byte{0xFE, 0xED, 0xFA, 0xCF}, "Mach-O 64-bit"},
	}

	// Search beyond the first 16 bytes (skip the legitimate header)
	searchStart := 16
	if len(data) <= searchStart {
		return nil
	}

	for _, em := range execMagics {
		idx := bytesIndex(data[searchStart:], em.magic)
		if idx >= 0 {
			return &FileFinding{
				Type: "embedded_executable",
				Description: em.name + " signature found embedded inside " + ext +
					" file at offset " + itoa(searchStart+idx),
				Severity: core.SeverityCritical,
			}
		}
	}

	return nil
}

// checkShellcode scans for known shellcode byte patterns in file content.
func (fs *FileSentinel) checkShellcode(data []byte) []FileFinding {
	var findings []FileFinding
	for _, sig := range shellcodeSignatures {
		if idx := bytesIndex(data, sig.pattern); idx >= 0 {
			findings = append(findings, FileFinding{
				Type:        "shellcode_signature",
				Description: sig.name + " detected at offset " + itoa(idx),
				Severity:    core.SeverityCritical,
			})
		}
	}
	return findings
}

// checkEntropyAnomaly flags files with unusually high entropy for their type.
// Compressed/encrypted content in a supposedly plain format suggests packing.
func (fs *FileSentinel) checkEntropyAnomaly(data []byte, declaredExt string) *FileFinding {
	ext := strings.ToLower(strings.TrimPrefix(declaredExt, "."))

	// These formats are naturally high-entropy, skip them
	highEntropyFormats := map[string]bool{
		"zip": true, "gz": true, "tar": true, "7z": true, "rar": true,
		"jpg": true, "jpeg": true, "png": true, "webp": true, "mp4": true,
		"mp3": true, "ogg": true, "flac": true, "aes": true, "gpg": true,
	}
	if highEntropyFormats[ext] {
		return nil
	}

	entropy := shannonEntropy(data)

	// Entropy > 7.5 in a non-compressed format is suspicious (max is 8.0)
	if entropy > 7.5 {
		return &FileFinding{
			Type:        "high_entropy",
			Description: "Unusually high entropy (" + ftoa(entropy) + "/8.0) for " + ext + " file — possible encrypted/packed payload",
			Severity:    core.SeverityHigh,
		}
	}

	return nil
}

// checkOversizedHeaders detects malformed image/document headers with
// abnormally large dimension or size fields — a common heap overflow vector.
func (fs *FileSentinel) checkOversizedHeaders(data []byte, declaredExt string) *FileFinding {
	ext := strings.ToLower(strings.TrimPrefix(declaredExt, "."))

	switch ext {
	case "png":
		return fs.checkPNGHeaders(data)
	case "bmp":
		return fs.checkBMPHeaders(data)
	case "gif":
		return fs.checkGIFHeaders(data)
	}

	return nil
}

func (fs *FileSentinel) checkPNGHeaders(data []byte) *FileFinding {
	// PNG IHDR chunk starts at offset 8, width at 16, height at 20 (big-endian uint32)
	if len(data) < 24 {
		return nil
	}
	width := binary.BigEndian.Uint32(data[16:20])
	height := binary.BigEndian.Uint32(data[20:24])
	// Unreasonable dimensions suggest crafted header for heap overflow
	if width > 65535 || height > 65535 {
		return &FileFinding{
			Type:        "oversized_header",
			Description: "PNG with extreme dimensions (" + uitoa(width) + "x" + uitoa(height) + ") — potential heap overflow via image parser",
			Severity:    core.SeverityHigh,
		}
	}
	return nil
}

func (fs *FileSentinel) checkBMPHeaders(data []byte) *FileFinding {
	// BMP: width at offset 18, height at offset 22 (little-endian int32)
	if len(data) < 26 {
		return nil
	}
	width := binary.LittleEndian.Uint32(data[18:22])
	height := binary.LittleEndian.Uint32(data[22:26])
	if width > 65535 || height > 65535 {
		return &FileFinding{
			Type:        "oversized_header",
			Description: "BMP with extreme dimensions — potential heap overflow via image parser",
			Severity:    core.SeverityHigh,
		}
	}
	return nil
}

func (fs *FileSentinel) checkGIFHeaders(data []byte) *FileFinding {
	// GIF: width at offset 6, height at offset 8 (little-endian uint16)
	if len(data) < 10 {
		return nil
	}
	width := binary.LittleEndian.Uint16(data[6:8])
	height := binary.LittleEndian.Uint16(data[8:10])
	// GIF max is 65535 but anything over 10000 in practice is suspicious
	if width > 10000 || height > 10000 {
		return &FileFinding{
			Type:        "oversized_header",
			Description: "GIF with extreme dimensions — potential parser exploit",
			Severity:    core.SeverityMedium,
		}
	}
	return nil
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func identifyByMagic(data []byte) string {
	for ext, magic := range knownMagic {
		if len(data) >= len(magic) {
			match := true
			for i, b := range magic {
				if data[i] != b {
					match = false
					break
				}
			}
			if match {
				return ext
			}
		}
	}
	return "unknown"
}

func bytesIndex(data, pattern []byte) int {
	if len(pattern) == 0 || len(data) < len(pattern) {
		return -1
	}
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j, b := range pattern {
			if data[i+j] != b {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]float64
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	entropy := 0.0
	for _, f := range freq {
		if f > 0 {
			p := f / n
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	if neg {
		s = "-" + s
	}
	return s
}

func uitoa(n uint32) string {
	return itoa(int(n))
}

func ftoa(f float64) string {
	whole := int(f)
	frac := int((f - float64(whole)) * 100)
	if frac < 0 {
		frac = -frac
	}
	s := itoa(whole) + "."
	if frac < 10 {
		s += "0"
	}
	s += itoa(frac)
	return s
}
