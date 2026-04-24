import json, os, re, subprocess, threading
import tkinter as tk
from tkinter import filedialog, ttk

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(SCRIPT_DIR)

LILAC = "#C8A2C8"
RESULTS_FILENAME = "scan_results.txt"
SCANNER_EXE_NAME = "aldnoah_scanner.exe"
TEXT_ENCODINGS = ("utf-8", "shift_jis", "big5")


def setup_lilac_styles():
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure("Lilac.TFrame", background=LILAC)
    style.configure("Lilac.TLabel", background=LILAC, foreground="black", padding=0)
    style.map("Lilac.TLabel", background=[("active", LILAC)])


def normalize_hex_pattern(value: str) -> str:
    cleaned = re.sub(r"[\s_]+", "", value).upper()
    if not cleaned:
        raise ValueError("Pattern cannot be empty.")
    if len(cleaned) % 2 != 0:
        raise ValueError("Hex string length must be even.")

    for idx in range(0, len(cleaned), 2):
        pair = cleaned[idx:idx + 2]
        if pair == "??":
            continue
        try:
            int(pair, 16)
        except ValueError as exc:
            raise ValueError(f"Invalid hex pair '{pair}'.") from exc

    return cleaned


def encode_text_pattern(value: str, encoding: str) -> str:
    try:
        return value.encode(encoding, errors="strict").hex().upper()
    except LookupError as exc:
        raise ValueError(f"Unsupported encoding: {encoding}") from exc
    except UnicodeEncodeError as exc:
        raise ValueError(str(exc)) from exc


def resolve_scanner_command():
    exe_path = os.path.join(SCRIPT_DIR, SCANNER_EXE_NAME)
    if os.path.isfile(exe_path):
        return [exe_path], exe_path

    raise FileNotFoundError(
        f"Could not find {SCANNER_EXE_NAME} in {SCRIPT_DIR}."
    )


class Scanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Aldnoah Batch File Scanner")
        self.root.geometry("1250x730")
        self.root.resizable(False, False)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        setup_lilac_styles()

        self.dir_var = tk.StringVar(value="No directory selected")
        self.mode_var = tk.StringVar(value="hex")
        self.pattern_var = tk.StringVar()
        self.encoding_var = tk.StringVar(value="utf-8")
        self.comp_var = tk.StringVar(value="none")
        self.zlib_level_var = tk.IntVar(value=6)

        self.status_var = tk.StringVar(value="Idle")
        self.progress_label_var = tk.StringVar(value="Progress: waiting to start.")
        self.current_file_var = tk.StringVar(value="Current file: none")

        self.scan_running = False
        self.total_files = 0
        self.current_results_path = os.path.join(SCRIPT_DIR, RESULTS_FILENAME)
        self.current_process = None
        self._done_event_received = False
        self._error_event_received = False
        self._counting_started = False

        self.build_gui()

    def build_gui(self):
        self.bg = ttk.Frame(self.root, style="Lilac.TFrame")
        self.bg.place(x=0, y=0, relwidth=1, relheight=1)

        self.open_btn = ttk.Button(
            self.bg,
            text="Select directory to scan",
            command=self.select_directory,
        )
        self.open_btn.place(x=20, y=20)

        dir_label = ttk.Label(
            self.bg,
            textvariable=self.dir_var,
            style="Lilac.TLabel",
        )
        dir_label.place(x=240, y=24)

        mode_label = ttk.Label(self.bg, text="Search mode:", style="Lilac.TLabel")
        mode_label.place(x=20, y=60)

        self.hex_radio = ttk.Radiobutton(
            self.bg,
            text="Hex",
            variable=self.mode_var,
            value="hex",
            command=self.update_encoding_state,
        )
        self.hex_radio.place(x=120, y=60)

        self.text_radio = ttk.Radiobutton(
            self.bg,
            text="Text",
            variable=self.mode_var,
            value="text",
            command=self.update_encoding_state,
        )
        self.text_radio.place(x=180, y=60)

        patt_label = ttk.Label(self.bg, text="Pattern:", style="Lilac.TLabel")
        patt_label.place(x=20, y=100)

        self.pattern_entry = ttk.Entry(self.bg, textvariable=self.pattern_var, width=60)
        self.pattern_entry.place(x=90, y=100)

        self.paste_btn = ttk.Button(
            self.bg,
            text="Paste",
            command=self.paste_pattern_from_clipboard,
        )
        self.paste_btn.place(x=700, y=96)

        enc_label = ttk.Label(self.bg, text="Encoding (text mode):", style="Lilac.TLabel")
        enc_label.place(x=20, y=140)

        self.enc_box = ttk.Combobox(
            self.bg,
            textvariable=self.encoding_var,
            values=TEXT_ENCODINGS,
            state="readonly",
            width=12,
        )
        self.enc_box.place(x=170, y=140)

        comp_label = ttk.Label(self.bg, text="Compression:", style="Lilac.TLabel")
        comp_label.place(x=340, y=140)

        self.comp_box = ttk.Combobox(
            self.bg,
            textvariable=self.comp_var,
            values=("none", "zlib"),
            state="readonly",
            width=10,
        )
        self.comp_box.place(x=430, y=140)

        level_label = ttk.Label(self.bg, text="Level:", style="Lilac.TLabel")
        level_label.place(x=540, y=140)

        self.level_spin = ttk.Spinbox(
            self.bg,
            from_=1,
            to=9,
            textvariable=self.zlib_level_var,
            width=3,
        )
        self.level_spin.place(x=600, y=140)

        self.scan_btn = ttk.Button(
            self.bg,
            text="Start Scan",
            command=self.start_scan,
            state=tk.DISABLED,
        )
        self.scan_btn.place(x=20, y=180)

        status_label = ttk.Label(self.bg, textvariable=self.status_var, style="Lilac.TLabel")
        status_label.place(x=130, y=184)

        progress_label = ttk.Label(
            self.bg,
            textvariable=self.progress_label_var,
            style="Lilac.TLabel",
        )
        progress_label.place(x=20, y=214)

        current_file_label = ttk.Label(
            self.bg,
            textvariable=self.current_file_var,
            style="Lilac.TLabel",
        )
        current_file_label.place(x=20, y=234)

        self.progress_bar = ttk.Progressbar(
            self.bg,
            orient="horizontal",
            mode="determinate",
            maximum=100,
            length=960,
        )
        self.progress_bar.place(x=260, y=234, width=960)

        self.result_text = tk.Text(self.bg, wrap="none")
        self.result_text.place(x=20, y=270, width=1210, height=410)

        scroll_y = tk.Scrollbar(self.bg, orient="vertical", command=self.result_text.yview)
        scroll_y.place(x=1230, y=270, height=410)

        scroll_x = tk.Scrollbar(self.bg, orient="horizontal", command=self.result_text.xview)
        scroll_x.place(x=20, y=680, width=1210)

        self.result_text.configure(
            yscrollcommand=scroll_y.set,
            xscrollcommand=scroll_x.set,
        )

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
            allowed = "0123456789ABCDEFabcdef? \t\r\n_"
            text = "".join(ch for ch in text if ch in allowed)
            text = re.sub(r"\s+", " ", text).strip()

        self.pattern_var.set(text)
        self.status_var.set("Pattern pasted from clipboard.")

    def select_directory(self):
        path = filedialog.askdirectory()
        if path:
            self.dir_var.set(path)
        self.update_scan_button_state()

    def set_controls_for_scan(self, running: bool):
        button_state = tk.DISABLED if running else tk.NORMAL
        radio_state = tk.DISABLED if running else tk.NORMAL
        entry_state = tk.DISABLED if running else tk.NORMAL
        spin_state = tk.DISABLED if running else tk.NORMAL
        combo_state = "disabled" if running else "readonly"

        self.open_btn.config(state=button_state)
        self.hex_radio.config(state=radio_state)
        self.text_radio.config(state=radio_state)
        self.pattern_entry.config(state=entry_state)
        self.paste_btn.config(state=button_state)
        self.comp_box.config(state=combo_state)
        self.level_spin.config(state=spin_state)

        if running:
            self.enc_box.config(state="disabled")
            self.scan_btn.config(state=tk.DISABLED)
        else:
            self.update_encoding_state()
            self.update_scan_button_state()

    def update_scan_button_state(self, *args):
        if self.scan_running:
            self.scan_btn.config(state=tk.DISABLED)
            return

        dir_ok = os.path.isdir(self.dir_var.get())
        patt_ok = bool(self.pattern_var.get().strip())
        self.scan_btn.config(state=tk.NORMAL if dir_ok and patt_ok else tk.DISABLED)

    def update_encoding_state(self, *args):
        if getattr(self, "enc_box", None) is None:
            return
        if self.scan_running:
            self.enc_box.config(state="disabled")
            return
        if self.mode_var.get() == "hex":
            self.enc_box.config(state="disabled")
        else:
            self.enc_box.config(state="readonly")

    def prepare_request(self):
        root_dir = self.dir_var.get()
        pattern_str = self.pattern_var.get().strip()
        mode = self.mode_var.get()
        encoding = self.encoding_var.get().strip() or "utf-8"
        compression = self.comp_var.get()

        if not os.path.isdir(root_dir):
            raise ValueError("Please select a valid directory.")
        if not pattern_str:
            raise ValueError("Please enter a pattern.")

        try:
            zlib_level = int(self.zlib_level_var.get())
        except (TypeError, ValueError):
            zlib_level = 6

        if not 1 <= zlib_level <= 9:
            zlib_level = 6

        if mode == "hex":
            pattern_hex = normalize_hex_pattern(pattern_str)
        else:
            pattern_hex = encode_text_pattern(pattern_str, encoding)

        return {
            "root_dir": root_dir,
            "mode": mode,
            "encoding": encoding,
            "compression": compression,
            "zlib_level": zlib_level,
            "pattern_hex": pattern_hex,
            "pattern_display": pattern_str,
            "results_path": self.current_results_path,
        }

    def start_counting_ui(self):
        if self._counting_started:
            return
        self._counting_started = True
        self.progress_bar.stop()
        self.progress_bar.configure(mode="indeterminate")
        self.progress_bar.start(10)
        self.progress_label_var.set("Counting files")
        self.status_var.set("Counting files")
        self.current_file_var.set("Current file: building file list")

    def start_scanning_ui(self, total_files: int):
        self.total_files = total_files
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate", maximum=100)
        self.progress_bar["value"] = 0
        self.progress_label_var.set(f"0 / {total_files:,} files (0.00%)")
        self.status_var.set("Scanning")
        self.current_file_var.set("Current file: waiting for worker activity")

    def shorten_path(self, value: str, limit: int = 140) -> str:
        if len(value) <= limit:
            return value
        keep = max(20, (limit - 3) // 2)
        return f"{value[:keep]}{value[-keep:]}"

    def update_progress_ui(
        self,
        files_scanned: int,
        total_files: int,
        hits: int,
        percent: float,
        current_file: str = "",
    ):
        self.progress_bar["value"] = max(0.0, min(percent, 100.0))
        self.progress_label_var.set(
            f"{files_scanned:,} / {total_files:,} files ({percent:.2f}%)"
        )
        self.status_var.set(
            f"Scanning Files: {files_scanned:,}/{total_files:,} Hits: {hits:,}"
        )
        if current_file:
            self.current_file_var.set(
                f"Current file: {self.shorten_path(current_file)}"
            )

    def load_results_into_text(self):
        try:
            with open(self.current_results_path, "r", encoding="utf-8") as handle:
                content = handle.read()
        except OSError:
            content = (
                "Scan finished, but the results file could not be read:\n"
                f"{self.current_results_path}"
            )

        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, content)
        self.result_text.see("1.0")

    def handle_scanner_event(self, event):
        event_type = event.get("type")
        if event_type == "counting":
            self.start_counting_ui()
            files_counted = int(event.get("files_counted", 0))
            self.progress_label_var.set(f"Counting files {files_counted:,} found so far")
            self.status_var.set(f"Counting files {files_counted:,} found so far")
            return

        if event_type == "start":
            total_files = int(event.get("total_files", 0))
            self.current_results_path = event.get("results_path", self.current_results_path)
            self.start_scanning_ui(total_files)
            return

        if event_type == "progress":
            files_scanned = int(event.get("files_scanned", 0))
            total_files = int(event.get("total_files", self.total_files))
            hits = int(event.get("hits", 0))
            percent = float(event.get("percent", 0.0))
            current_file = event.get("current_file", "")
            self.update_progress_ui(
                files_scanned,
                total_files,
                hits,
                percent,
                current_file,
            )
            return

        if event_type == "done":
            self._done_event_received = True
            files_scanned = int(event.get("files_scanned", 0))
            total_files = int(event.get("total_files", self.total_files))
            hits = int(event.get("hits", 0))
            percent = float(event.get("percent", 100.0))
            self.update_progress_ui(files_scanned, total_files, hits, percent)
            self.current_results_path = event.get("results_path", self.current_results_path)
            self.load_results_into_text()
            self.status_var.set(
                f"Done. Files: {files_scanned:,}/{total_files:,} Hits: {hits:,}. "
                f"Results saved to: {self.current_results_path}"
            )
            self.current_file_var.set("Current file: scan complete")
            return

        if event_type == "error":
            self._error_event_received = True
            message = event.get("message", "Scanner error.")
            self.progress_bar.stop()
            self.progress_bar.configure(mode="determinate", maximum=100)
            self.status_var.set(f"Error: {message}")
            self.current_file_var.set("Current file: scanner stopped")
            self.result_text.insert(tk.END, f"ERROR: {message}\n")
            self.result_text.see(tk.END)

    def finalize_scan(self, returncode: int, stderr_output: str):
        self.scan_running = False
        self.current_process = None
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate", maximum=100)
        self.set_controls_for_scan(False)

        if self._done_event_received or self._error_event_received:
            return

        if returncode == 0:
            message = "Scanner finished without sending a completion message."
        else:
            message = stderr_output.strip() or f"Scanner exited with code {returncode}."

        self.status_var.set(f"Error: {message}")
        self.result_text.insert(tk.END, f"ERROR: {message}\n")
        self.result_text.see(tk.END)

    def scanner_worker(self, request):
        stderr_output = ""
        returncode = 1

        try:
            command, _ = resolve_scanner_command()

            creationflags = 0
            startupinfo = None
            if os.name == "nt":
                creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                if hasattr(subprocess, "SW_HIDE"):
                    startupinfo.wShowWindow = subprocess.SW_HIDE

            proc = subprocess.Popen(
                [*command, "--json"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                bufsize=1,
                creationflags=creationflags,
                startupinfo=startupinfo,
            )
            self.current_process = proc

            if proc.stdin is not None:
                proc.stdin.write(json.dumps(request))
                proc.stdin.close()

            if proc.stdout is not None:
                for line in proc.stdout:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    self.root.after(0, self.handle_scanner_event, event)

            if proc.stderr is not None:
                stderr_output = proc.stderr.read()

            returncode = proc.wait()
        except Exception as exc:
            self.root.after(
                0,
                self.handle_scanner_event,
                {"type": "error", "message": str(exc)},
            )
            self._error_event_received = True
        finally:
            self.root.after(0, self.finalize_scan, returncode, stderr_output)

    def start_scan(self):
        if self.scan_running:
            return

        self.current_results_path = os.path.join(SCRIPT_DIR, RESULTS_FILENAME)

        try:
            request = self.prepare_request()
        except ValueError as exc:
            self.status_var.set(str(exc))
            return

        self.scan_running = True
        self.total_files = 0
        self._done_event_received = False
        self._error_event_received = False
        self._counting_started = False

        self.result_text.delete("1.0", tk.END)
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate", maximum=100)
        self.progress_bar["value"] = 0
        self.progress_label_var.set("Waiting for scanner")
        self.current_file_var.set("Current file: starting scanner")
        self.status_var.set("Starting scanner")
        self.set_controls_for_scan(True)

        thread = threading.Thread(target=self.scanner_worker, args=(request,), daemon=True)
        thread.start()

    def on_close(self):
        proc = self.current_process
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
            except OSError:
                pass
        self.root.destroy()


def main():
    root = tk.Tk()
    Scanner(root)
    root.mainloop()


if __name__ == "__main__":
    main()
