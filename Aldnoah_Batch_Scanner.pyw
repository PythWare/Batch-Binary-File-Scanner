import os, zlib, re, threading, mmap
import tkinter as tk
from tkinter import ttk, filedialog
from dataclasses import dataclass

LILAC = "#C8A2C8"
MMAP_THRESHOLD = 50 * 1024 * 1024  # 50 MB

"""
My attempt at a professional level binary file scanner, best used when needing to scan large amounts of files
for strings/data. It's way faster than you opening thousands of files in a hex editor one by one to find what you need.

"""
@dataclass
class ScanProgress:
    files_scanned: int = 0
    hits: int = 0

def setup_lilac_styles():
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure("Lilac.TFrame",  background=LILAC)
    style.configure("Lilac.TLabel",  background=LILAC, foreground="black", padding=0)
    style.map("Lilac.TLabel", background=[("active", LILAC)])

def parse_hex_pattern(s: str) -> bytes:
    """
    Accepts inputs like 01 02 0A or 01020A and returns b'\\x01\\x02\\x0A'
    """
    cleaned = s.replace(" ", "").replace("_", "")
    if len(cleaned) % 2 != 0:
        raise ValueError("Hex string length must be even")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as e:
        raise ValueError(f"Invalid hex string: {e}")

def prepare_hex_pattern_with_wildcards(s: str):
    """
    Accepts things like 01 02 ?? 04 or 0102??04 and returns pattern_bytes, mask_bytes, and has_wildcards
    mask_bytes[i] == 1 -> byte must match exactly
    mask_bytes[i] == 0 -> wildcard (any byte)
    """
    cleaned = s.replace(" ", "").replace("_", "")
    if len(cleaned) % 2 != 0:
        raise ValueError("Hex string length must be even")

    pattern = []
    mask = []
    has_wild = False

    for i in range(0, len(cleaned), 2):
        pair = cleaned[i:i+2]
        if pair == "??":
            pattern.append(0)
            mask.append(0)     # wildcard
            has_wild = True
        else:
            try:
                value = int(pair, 16)
            except ValueError as e:
                raise ValueError(f"Invalid hex pair '{pair}': {e}")
            pattern.append(value)
            mask.append(1)  # real byte must match

    return bytes(pattern), bytes(mask), has_wild

def find_wildcard_matches(data: bytes, pattern: bytes, mask: bytes):
    """
    Returns all indices where pattern matches data using mask, 1 = exact byte while 0 = wildcard
    Also uses an anchor based search for speed
    """
    hits = []
    n = len(data)
    m = len(pattern)

    if m == 0 or n < m:
        return hits

    mv = memoryview(data)

    anchor_start, anchor_len = _find_best_anchor(pattern, mask)

    if anchor_len == 0:
        return hits

    anchor = bytes(pattern[anchor_start:anchor_start + anchor_len])

    search_pos = 0
    while True:
        idx = mv.find(anchor, search_pos)
        if idx == -1:
            break

        candidate = idx - anchor_start

        if 0 <= candidate and candidate + m <= n:
            ok = True
            for j in range(m):
                if mask[j] and mv[candidate + j] != pattern[j]:
                    ok = False
                    break
            if ok:
                hits.append(candidate)

        search_pos = idx + 1

    return hits

def _find_best_anchor(pattern: bytes, mask: bytes):
    """
    Find the longest contiguous run of non-wildcard bytes
    Returns anchor_start and anchor_len
    If there are no non-wildcard bytes, anchor_len will be 0
    """
    best_start = 0
    best_len = 0
    cur_start = 0
    cur_len = 0

    for i, m in enumerate(mask):
        if m:
            if cur_len == 0:
                cur_start = i
            cur_len += 1
            if cur_len > best_len:
                best_len = cur_len
                best_start = cur_start
        else:
            cur_len = 0

    return best_start, best_len

def build_wildcard_regex(pattern: bytes, mask: bytes):
    """
    Build a bytes regex from pattern and mask
    mask[i] == 1 -> that byte must match exactly
    mask[i] == 0 -> wildcard '??' -> '.'
    Returns a compiled regex or None if everything is wildcard
    """
    if not any(mask):
        return None

    parts = []
    for b, m in zip(pattern, mask):
        if m:
            parts.append(re.escape(bytes([b])))
        else:
            parts.append(b'.')

    regex_bytes = b''.join(parts)
    return re.compile(regex_bytes, re.DOTALL)

def get_search_bytes(mode: str, user_input: str, encoding: str = "utf-8") -> bytes:
    if mode == "hex":
        return parse_hex_pattern(user_input)
    else:
        return user_input.encode(encoding, errors="strict")

def scan_files(root_dir: str, target_bytes: bytes, out_path: str,
               progress: "ScanProgress | None" = None):
    """
    Recursively scan root_dir for target_bytes
    Uses mmap for large files to avoid loading them fully into RAM
    Writes results to out_path too incase anybody would like a file documenting the results
    """
    hits = 0
    files_checked = 0

    with open(out_path, "w", encoding="utf-8") as log:
        log.write(f"Search root: {root_dir}\n")
        log.write(f"Searched bytes (hex): {target_bytes.hex().upper()}\n\n")

        for dirpath, dirnames, filenames in os.walk(root_dir):
            for fname in filenames:
                fpath = os.path.join(dirpath, fname)

                try:
                    size = os.path.getsize(fpath)
                except OSError:
                    continue

                if size == 0:
                    continue

                files_checked += 1
                if progress is not None:
                    progress.files_scanned += 1

                try:
                    with open(fpath, "rb") as f:
                        if size >= MMAP_THRESHOLD:
                            try:
                                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                                    data = mm
                                    start = 0
                                    local_found = False
                                    while True:
                                        idx = data.find(target_bytes, start)
                                        if idx == -1:
                                            break
                                        if not local_found:
                                            log.write(f"FILE: {fpath}\n")
                                            local_found = True
                                        hits += 1
                                        if progress is not None:
                                            progress.hits += 1
                                        log.write(f"  offset: 0x{idx:X} ({idx} decimal)\n")
                                        start = idx + 1
                                    if local_found:
                                        log.write("\n")
                            except (OSError, ValueError):
                                continue
                        else:
                            data = f.read()
                            start = 0
                            local_found = False
                            while True:
                                idx = data.find(target_bytes, start)
                                if idx == -1:
                                    break
                                if not local_found:
                                    log.write(f"FILE: {fpath}\n")
                                    local_found = True
                                hits += 1
                                if progress is not None:
                                    progress.hits += 1
                                log.write(f"  offset: 0x{idx:X} ({idx} decimal)\n")
                                start = idx + 1
                            if local_found:
                                log.write("\n")
                except (OSError, IOError):
                    continue

        log.write(f"---\nFiles scanned: {files_checked}, total hits: {hits}\n")

def scan_files_wildcards(root_dir: str, pat_len: int, regex, out_path: str,
                         progress: "ScanProgress | None" = None):
    """
    Wildcard scan using a compiled bytes regex for speed
    Uses mmap for large files
    pat_len is the pattern length in bytes for quick size check
    regex is the compiled pattern from build_wildcard_regex()
    """
    hits = 0
    files_checked = 0

    with open(out_path, "w", encoding="utf-8") as log:
        log.write(f"Search root: {root_dir}\n")
        log.write(f"Pattern length: {pat_len} bytes\n")
        log.write("Wildcards: '??' match any byte.\n\n")

        for dirpath, dirnames, filenames in os.walk(root_dir):
            for fname in filenames:
                fpath = os.path.join(dirpath, fname)

                try:
                    size = os.path.getsize(fpath)
                except OSError:
                    continue

                if size < pat_len:
                    continue

                files_checked += 1
                if progress is not None:
                    progress.files_scanned += 1

                try:
                    with open(fpath, "rb") as f:
                        if size >= MMAP_THRESHOLD:
                            try:
                                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                                    matches = list(regex.finditer(mm))
                            except (OSError, ValueError):
                                continue
                        else:
                            data = f.read()
                            matches = list(regex.finditer(data))
                except (OSError, IOError):
                    continue

                if matches:
                    log.write(f"FILE: {fpath}\n")
                    for m in matches:
                        idx = m.start()
                        hits += 1
                        if progress is not None:
                            progress.hits += 1
                        log.write(f"  offset: 0x{idx:X} ({idx} decimal)\n")
                    log.write("\n")

        log.write(f"---\nFiles scanned: {files_checked}, total hits: {hits}\n")

class Scanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Aldnoah Batch File Scanner")
        self.root.geometry("1250x700")
        self.root.resizable(False, False)

        setup_lilac_styles()

        # state vars
        self.dir_var = tk.StringVar(value="No directory selected")
        self.mode_var = tk.StringVar(value="hex")  # hex or text
        self.pattern_var = tk.StringVar()

        # Encoding combobox var. defaults to first item which is utf-8
        self.encoding_var = tk.StringVar(value="utf-8")

        self.status_var = tk.StringVar(value="Idle")
        self.comp_var = tk.StringVar(value="none")
        self.zlib_level_var = tk.IntVar(value=6)

        self.progress = None
        self._progress_running = False

        self.build_gui()

    def _update_progress(self):
        if not self._progress_running:
            return

        if self.progress is not None:
            self.status_var.set(
                f"Scanning... Files scanned: {self.progress.files_scanned}, "
                f"hits: {self.progress.hits}"
            )

        self.root.after(200, self._update_progress)

    def build_gui(self):
        """Handles the buildong of the GUI design"""
        self.bg = ttk.Frame(self.root, style="Lilac.TFrame")
        self.bg.place(x=0, y=0, relwidth=1, relheight=1)

        open_btn = ttk.Button(
            self.bg,
            text="Select directory to scan",
            command=self.select_directory
        )
        open_btn.place(x=20, y=20)

        dir_label = ttk.Label(
            self.bg,
            textvariable=self.dir_var,
            style="Lilac.TLabel"
        )
        dir_label.place(x=240, y=24)

        mode_label = ttk.Label(self.bg, text="Search mode:", style="Lilac.TLabel")
        mode_label.place(x=20, y=60)

        hex_radio = ttk.Radiobutton(
            self.bg,
            text="Hex",
            variable=self.mode_var,
            value="hex",
            command=self._update_encoding_state
        )
        hex_radio.place(x=120, y=60)

        text_radio = ttk.Radiobutton(
            self.bg,
            text="Text",
            variable=self.mode_var,
            value="text",
            command=self._update_encoding_state
        )
        text_radio.place(x=180, y=60)

        patt_label = ttk.Label(self.bg, text="Pattern:", style="Lilac.TLabel")
        patt_label.place(x=20, y=100)

        patt_entry = ttk.Entry(self.bg, textvariable=self.pattern_var, width=60)
        patt_entry.place(x=90, y=100)

        paste_btn = ttk.Button(
            self.bg,
            text="Paste",
            command=self.paste_pattern_from_clipboard
        )
        paste_btn.place(x=700, y=96)

        enc_label = ttk.Label(self.bg, text="Encoding (text mode):", style="Lilac.TLabel")
        enc_label.place(x=20, y=140)

        enc_box = ttk.Combobox(
            self.bg,
            textvariable=self.encoding_var,
            values=("utf-8", "shift_jis", "big5"),
            state="readonly",
            width=12
        )
        enc_box.place(x=170, y=140)

        self.enc_box = enc_box  # for enable and disabling based on mode

        # Compression mode, incase someone needs to search a compressed string or bytes
        comp_label = ttk.Label(self.bg, text="Compression:", style="Lilac.TLabel")
        comp_label.place(x=340, y=140)

        comp_box = ttk.Combobox(
            self.bg,
            textvariable=self.comp_var,
            values=("none", "zlib"),
            state="readonly",
            width=10
        )
        comp_box.place(x=430, y=140)

        level_label = ttk.Label(self.bg, text="Level:", style="Lilac.TLabel")
        level_label.place(x=540, y=140)

        level_spin = ttk.Spinbox(
            self.bg,
            from_=1,
            to=9,
            textvariable=self.zlib_level_var,
            width=3
        )
        level_spin.place(x=600, y=140)

        self.scan_btn = ttk.Button(
            self.bg,
            text="Start Scan",
            command=self.start_scan,
            state=tk.DISABLED
        )
        self.scan_btn.place(x=20, y=180)

        status_label = ttk.Label(self.bg, textvariable=self.status_var, style="Lilac.TLabel")
        status_label.place(x=130, y=184)

        self.result_text = tk.Text(self.bg, wrap="none")
        self.result_text.place(x=20, y=220, width=1210, height=450)

        scroll_y = tk.Scrollbar(self.bg, orient="vertical", command=self.result_text.yview)
        scroll_y.place(x=1230, y=220, height=450)

        self.result_text.configure(yscrollcommand=scroll_y.set)

        self.pattern_var.trace_add("write", self._update_scan_button_state)

        self._update_encoding_state()

    def paste_pattern_from_clipboard(self):
        try:
            text = self.root.clipboard_get()
        except tk.TclError:
            self.status_var.set("Clipboard is empty or not text.")
            return

        text = text.strip()

        if self.mode_var.get() == "hex":
            allowed = "0123456789ABCDEFabcdef? "
            cleaned_chars = []
            for ch in text:
                if ch in allowed:
                    cleaned_chars.append(ch)
            cleaned = "".join(cleaned_chars)

            normalized = []
            last_space = False
            for ch in cleaned:
                if ch == " ":
                    if not last_space:
                        normalized.append(" ")
                        last_space = True
                else:
                    normalized.append(ch)
                    last_space = False
            text = "".join(normalized).strip()

        self.pattern_var.set(text)
        self.status_var.set("Pattern pasted from clipboard.")

    def select_directory(self):
        path = filedialog.askdirectory()
        if path:
            self.dir_var.set(path)
        self._update_scan_button_state()

    def _update_scan_button_state(self, *args):
        dir_ok = os.path.isdir(self.dir_var.get())
        patt_ok = bool(self.pattern_var.get().strip())
        if dir_ok and patt_ok:
            self.scan_btn.config(state=tk.NORMAL)
        else:
            self.scan_btn.config(state=tk.DISABLED)

    def _update_encoding_state(self, *args):
        """Disable encoding selection in hex mode"""
        if getattr(self, "enc_box", None) is None:
            return
        if self.mode_var.get() == "hex":
            self.enc_box.config(state="disabled")
        else:
            self.enc_box.config(state="readonly")

    def start_scan(self):
        root_dir = self.dir_var.get()
        pattern_str = self.pattern_var.get().strip()
        mode = self.mode_var.get()
        encoding = self.encoding_var.get().strip() or "utf-8"

        if not os.path.isdir(root_dir):
            self.status_var.set("Please select a valid directory.")
            return
        if not pattern_str:
            self.status_var.set("Please enter a pattern.")
            return

        use_wildcards = False
        mask_bytes = None

        try:
            if mode == "hex":
                pattern_bytes, mask_bytes, has_wild = prepare_hex_pattern_with_wildcards(pattern_str)
                use_wildcards = has_wild
                base_bytes = pattern_bytes
            else:
                base_bytes = get_search_bytes("text", pattern_str, encoding)
        except ValueError as e:
            self.status_var.set(f"Error: {e}")
            return

        comp_mode = self.comp_var.get()

        if mode == "hex" and use_wildcards and comp_mode != "none":
            self.status_var.set("Wildcards are only supported with uncompressed hex search.")
            return

        try:
            if comp_mode == "zlib":
                try:
                    level = int(self.zlib_level_var.get())
                except (TypeError, ValueError):
                    level = 6

                if level < 1 or level > 9:
                    level = 6

                target_bytes = zlib.compress(base_bytes, level)
            else:
                target_bytes = base_bytes
        except Exception as e:
            self.status_var.set(f"Compression error: {e}")
            return

        out_path = os.path.join(os.getcwd(), "scan_results.txt")

        self.result_text.delete("1.0", tk.END)
        self.status_var.set("Scanning...")
        self.scan_btn.config(state=tk.DISABLED)

        self.progress = ScanProgress()
        self._progress_running = True
        self._update_progress()

        wildcard_regex = None
        pat_len = len(base_bytes)
        if mode == "hex" and use_wildcards:
            wildcard_regex = build_wildcard_regex(base_bytes, mask_bytes)
            if wildcard_regex is None:
                self.status_var.set("Pattern is all wildcards, refusing to match everything.")
                self.scan_btn.config(state=tk.NORMAL)
                return

        def worker():
            if mode == "hex" and use_wildcards:
                scan_files_wildcards(root_dir, pat_len, wildcard_regex, out_path, self.progress)
            else:
                scan_files(root_dir, target_bytes, out_path, self.progress)

            self._progress_running = False

            def on_done():
                try:
                    with open(out_path, "r", encoding="utf-8") as f:
                        content = f.read()
                except OSError:
                    content = f"Scan complete, but could not read log file:\n{out_path}"

                self.result_text.insert(tk.END, content)
                if self.progress is not None:
                    self.status_var.set(
                        f"Done. Files: {self.progress.files_scanned}, "
                        f"hits: {self.progress.hits}. "
                        f"Results saved to: {out_path}"
                    )
                else:
                    self.status_var.set(f"Done. Results saved to: {out_path}")

                self.scan_btn.config(state=tk.NORMAL)

            self.root.after(0, on_done)

        t = threading.Thread(target=worker, daemon=True)
        t.start()

def main():
    root = tk.Tk()
    checker = Scanner(root)
    root.mainloop()

if __name__ == "__main__":
    main()
