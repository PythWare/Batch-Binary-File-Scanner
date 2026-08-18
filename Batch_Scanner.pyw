import os, zlib, re, threading, mmap, multiprocessing, tempfile, shutil, time, queue
import tkinter as tk
from tkinter import ttk, filedialog
from dataclasses import dataclass

os.chdir(os.path.dirname(os.path.abspath(__file__)))

LILAC = "#C8A2C8"
MMAP_THRESHOLD = 50 * 1024 * 1024

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
    cleaned = s.replace(" ", "").replace("_", "")
    if len(cleaned) % 2 != 0:
        raise ValueError("Hex string length must be even")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as e:
        raise ValueError(f"Invalid hex string: {e}")

def prepare_hex_pattern_with_wildcards(s: str):
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
            mask.append(0)
            has_wild = True
        else:
            try:
                value = int(pair, 16)
            except ValueError as e:
                raise ValueError(f"Invalid hex pair '{pair}': {e}")
            pattern.append(value)
            mask.append(1)

    return bytes(pattern), bytes(mask), has_wild

def find_wildcard_matches(data: bytes, pattern: bytes, mask: bytes):
    hits = []
    n = len(data)
    m = len(pattern)

    if m == 0 or n < m:
        return hits

    mv = memoryview(data)

    anchor_start, anchor_len = find_best_anchor(pattern, mask)

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

def find_best_anchor(pattern: bytes, mask: bytes):
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

worker_state = {}

def init_worker(use_wildcards, target_bytes, pat_len, pattern_bytes, mask_bytes, progress_queue):
    global worker_state
    worker_state = {
        "use_wildcards": use_wildcards,
        "target_bytes": target_bytes,
        "pat_len": pat_len,
        "queue": progress_queue,
        "regex": build_wildcard_regex(pattern_bytes, mask_bytes) if use_wildcards else None,
    }

def find_matches(data, state):
    if state["use_wildcards"]:
        return [m.start() for m in state["regex"].finditer(data)]

    target = state["target_bytes"]
    hits = []
    start = 0
    while True:
        idx = data.find(target, start)
        if idx == -1:
            break
        hits.append(idx)
        start = idx + 1
    return hits

def scan_chunk(args):
    chunk_index, file_list, tmp_dir = args
    state = worker_state
    progress_queue = state["queue"]

    local_files = 0
    local_hits = 0
    out_tmp_path = os.path.join(tmp_dir, f"part_{chunk_index}.txt")

    with open(out_tmp_path, "w", encoding="utf-8") as log:
        for fpath in file_list:
            try:
                size = os.path.getsize(fpath)
            except OSError:
                continue

            matches = []
            try:
                with open(fpath, "rb") as f:
                    if size >= MMAP_THRESHOLD:
                        try:
                            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                                matches = find_matches(mm, state)
                        except (OSError, ValueError):
                            continue
                    else:
                        data = f.read()
                        matches = find_matches(data, state)
            except (OSError, IOError):
                continue

            local_files += 1

            if matches:
                log.write(f"FILE: {fpath}\n")
                for idx in matches:
                    local_hits += 1
                    log.write(f"  offset: 0x{idx:X} ({idx} decimal)\n")
                log.write("\n")

            progress_queue.put((1, len(matches)))

    return (chunk_index, local_files, local_hits, out_tmp_path)

def build_the_fucking_file_list(root_dir: str, min_size: int):
    files = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            try:
                size = os.path.getsize(fpath)
            except OSError:
                continue
            if size < min_size:
                continue
            files.append(fpath)
    return files

def scan_files_parallel(root_dir: str, mode_info: dict, out_path: str, num_workers: int,
                        progress: "ScanProgress | None" = None):

    use_wildcards = mode_info["use_wildcards"]
    pat_len = mode_info["pat_len"]
    min_size = pat_len if use_wildcards else 1

    file_list = build_the_fucking_file_list(root_dir, min_size)
    total_files = len(file_list)

    tmp_dir = tempfile.mkdtemp(prefix="batchscan_")

    if total_files == 0:
        chunks = []
    else:
        target_chunk_count = max(num_workers, min(num_workers * 8, total_files))
        chunk_size = max(1, -(-total_files // target_chunk_count))
        chunks = [file_list[i:i + chunk_size] for i in range(0, total_files, chunk_size)]

    manager = multiprocessing.Manager()
    progress_queue = manager.Queue()

    init_args = (
        use_wildcards,
        mode_info.get("target_bytes"),
        pat_len,
        mode_info.get("pattern_bytes"),
        mode_info.get("mask_bytes"),
        progress_queue,
    )

    results = []
    pool = multiprocessing.Pool(processes=num_workers, initializer=init_worker, initargs=init_args)
    try:
        async_results = [
            pool.apply_async(scan_chunk, ((idx, chunk, tmp_dir),))
            for idx, chunk in enumerate(chunks)
        ]
        pool.close()

        def drain_queue():
            try:
                while True:
                    delta_files, delta_hits = progress_queue.get_nowait()
                    if progress is not None:
                        progress.files_scanned += delta_files
                        progress.hits += delta_hits
            except queue.Empty:
                pass

        while not all(r.ready() for r in async_results):
            drain_queue()
            time.sleep(0.05)

        drain_queue()

        for r in async_results:
            results.append(r.get())
    finally:
        pool.join()
        manager.shutdown()

    results.sort(key=lambda r: r[0])

    total_checked = sum(r[1] for r in results)
    total_hits = sum(r[2] for r in results)

    with open(out_path, "w", encoding="utf-8") as final_log:
        for line in mode_info["header_lines"]:
            final_log.write(line)
        final_log.write("\n")

        for _, _, _, part_path in results:
            try:
                with open(part_path, "r", encoding="utf-8") as part_f:
                    final_log.write(part_f.read())
            except OSError:
                pass

        final_log.write(f"\nFiles scanned: {total_checked}, total hits: {total_hits}\n")

    shutil.rmtree(tmp_dir, ignore_errors=True)

    return total_checked, total_hits

def scan_files(root_dir: str, target_bytes: bytes, out_path: str,
               progress: "ScanProgress | None" = None):

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

        log.write(f"\nFiles scanned: {files_checked}, total hits: {hits}\n")

def scan_files_wildcards(root_dir: str, pat_len: int, regex, out_path: str,
                         progress: "ScanProgress | None" = None):

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

        log.write(f"\nFiles scanned: {files_checked}, total hits: {hits}\n")

class Scanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Kybernes Batch Binary File Scanner")
        self.root.geometry("1250x700")
        self.root.resizable(False, False)

        setup_lilac_styles()

        self.dir_var = tk.StringVar(value="No directory selected")
        self.mode_var = tk.StringVar(value="hex")
        self.pattern_var = tk.StringVar()
        self.encoding_var = tk.StringVar(value="utf-8")
        self.status_var = tk.StringVar(value="Idle")
        self.comp_var = tk.StringVar(value="none")
        self.zlib_level_var = tk.IntVar(value=6)

        self.cpu_count = os.cpu_count() or 1
        self.cores_var = tk.StringVar(value="")

        self.progress = None
        self.progress_running = False

        self.build_gui()

    def update_progress(self):
        if not self.progress_running:
            return

        if self.progress is not None:
            self.status_var.set(
                f"Scanning. Files scanned: {self.progress.files_scanned}, "
                f"hits: {self.progress.hits}"
            )

        self.root.after(200, self.update_progress)

    def build_gui(self):
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
            command=self.update_encoding_state
        )
        hex_radio.place(x=120, y=60)

        text_radio = ttk.Radiobutton(
            self.bg,
            text="Text",
            variable=self.mode_var,
            value="text",
            command=self.update_encoding_state
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

        self.enc_box = enc_box

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

        cores_label = ttk.Label(self.bg, text="CPU cores to use:", style="Lilac.TLabel")
        cores_label.place(x=20, y=170)

        cores_spin = ttk.Spinbox(
            self.bg,
            from_=1,
            to=self.cpu_count,
            textvariable=self.cores_var,
            width=3
        )
        cores_spin.place(x=160, y=170)

        cores_info = ttk.Label(
            self.bg,
            text=f"blank or 1 uses single process, 2 or more uses that many worker processes, {self.cpu_count} cores detected",
            style="Lilac.TLabel"
        )
        cores_info.place(x=210, y=170)

        self.scan_btn = ttk.Button(
            self.bg,
            text="Start Scan",
            command=self.start_scan,
            state=tk.DISABLED
        )
        self.scan_btn.place(x=20, y=210)

        status_label = ttk.Label(self.bg, textvariable=self.status_var, style="Lilac.TLabel")
        status_label.place(x=130, y=214)

        self.result_text = tk.Text(self.bg, wrap="none")
        self.result_text.place(x=20, y=250, width=1210, height=420)

        scroll_y = tk.Scrollbar(self.bg, orient="vertical", command=self.result_text.yview)
        scroll_y.place(x=1230, y=250, height=420)

        self.result_text.configure(yscrollcommand=scroll_y.set)

        self.pattern_var.trace_add("write", self.update_scan_button_state)

        self.update_encoding_state()

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
        self.update_scan_button_state()

    def update_scan_button_state(self, *args):
        dir_ok = os.path.isdir(self.dir_var.get())
        patt_ok = bool(self.pattern_var.get().strip())
        if dir_ok and patt_ok:
            self.scan_btn.config(state=tk.NORMAL)
        else:
            self.scan_btn.config(state=tk.DISABLED)

    def update_encoding_state(self, *args):
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
        self.scan_btn.config(state=tk.DISABLED)

        wildcard_regex = None
        pat_len = len(base_bytes)
        if mode == "hex" and use_wildcards:
            wildcard_regex = build_wildcard_regex(base_bytes, mask_bytes)
            if wildcard_regex is None:
                self.status_var.set("Pattern is all wildcards, refusing to match everything.")
                self.scan_btn.config(state=tk.NORMAL)
                return

        cores_str = self.cores_var.get().strip()
        if not cores_str:
            num_workers = 1
        else:
            try:
                num_workers = int(cores_str)
            except ValueError:
                num_workers = 1
            num_workers = max(1, min(num_workers, self.cpu_count))

        if num_workers > 1:
            self.status_var.set(f"Scanning with {num_workers} worker processes")
        else:
            self.status_var.set("Scanning")

        self.progress = ScanProgress()
        self.progress_running = True
        self.update_progress()

        def worker():
            start_time = time.time()

            if num_workers <= 1:
                if mode == "hex" and use_wildcards:
                    scan_files_wildcards(root_dir, pat_len, wildcard_regex, out_path, self.progress)
                else:
                    scan_files(root_dir, target_bytes, out_path, self.progress)
            else:
                if mode == "hex" and use_wildcards:
                    header_lines = [
                        f"Search root: {root_dir}\n",
                        f"Pattern length: {pat_len} bytes\n",
                        "Wildcards: '??' match any byte.\n",
                    ]
                else:
                    header_lines = [
                        f"Search root: {root_dir}\n",
                        f"Searched bytes (hex): {target_bytes.hex().upper()}\n",
                    ]

                mode_info = {
                    "use_wildcards": use_wildcards,
                    "target_bytes": target_bytes,
                    "pattern_bytes": base_bytes if use_wildcards else None,
                    "mask_bytes": mask_bytes if use_wildcards else None,
                    "pat_len": pat_len,
                    "header_lines": header_lines,
                }
                scan_files_parallel(root_dir, mode_info, out_path, num_workers, self.progress)

            elapsed = time.time() - start_time
            minutes, seconds = divmod(elapsed, 60)
            try:
                with open(out_path, "a", encoding="utf-8") as log:
                    log.write(f"Time spent: {int(minutes)} minutes, {seconds:.2f} seconds\n")
            except OSError:
                pass

            self.progress_running = False

            def on_done():
                try:
                    with open(out_path, "r", encoding="utf-8") as f:
                        content = f.read()
                except OSError:
                    content = f"Scan complete but couldnt read log file:\n{out_path}"

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
