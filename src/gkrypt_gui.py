import os
import re
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, Toplevel, Menu
from datetime import datetime
from gkrypt_core import encrypt_file, decrypt_file, WrongPasswordError, CorruptedFileError
from PIL import Image, ImageTk

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    DND_AVAILABLE = True
except ImportError:
    DND_AVAILABLE = False

LOG_DIR = "logs"
MAX_LOG_SIZE = 1 * 1024 * 1024
VERSION = "1.0"
ICON_FILE = "gkrypt.ico"

T = {
    'en': {
        'selected_files': "Selected Files:",
        'browse': "Browse Files",
        'password': "Password:",
        'confirm_password': "Confirm Password:",
        'output_folder': "Output Folder:",
        'select': "Select",
        'encrypt': "Encrypt",
        'decrypt': "Decrypt",
        'run': "Run",
        'view_log': "View Log",
        'about': "About",
        'error_pw_match': "Passwords do not match.",
        'error_pw_strength': "Your password should be at least 8 characters long and include uppercase, lowercase, digit and symbol.",
        'warning_no_files': "No files selected.",
        'prompt_delete': "Do you want to delete the original files after successful processing?",
        'title_delete': "Delete Originals?",
        'title_done': "GKrypt",
        'msg_done': "Done.\n\nSuccess:\n",
        'msg_errors': "\n\nErrors:\n",
        'msg_dnd': "Install tkinterdnd2 for drag and drop support.",
        'language': "Language:",
        'about_text': "GKrypt v{}\n\nCreated by GK\nSecure AES-256-GCM encryption\n© 2025",
        'invalid_format': "This file is not encrypted with GKrypt.",
    },
    'gr': {
        'selected_files': "Επιλεγμένα αρχεία:",
        'browse': "Αναζήτηση Αρχείων",
        'password': "Κωδικός:",
        'confirm_password': "Επιβεβαίωση Κωδικού:",
        'output_folder': "Φάκελος Εξόδου:",
        'select': "Επιλογή",
        'encrypt': "Κρυπτογράφηση",
        'decrypt': "Αποκρυπτογράφηση",
        'run': "Εκτέλεση",
        'view_log': "Προβολή Log",
        'about': "Πληροφορίες",
        'error_pw_match': "Οι κωδικοί δεν ταιριάζουν.",
        'error_pw_strength': "Ο κωδικός πρέπει να είναι τουλάχιστον 8 χαρακτήρες και να περιέχει κεφαλαία, πεζά, αριθμούς και σύμβολα.",
        'warning_no_files': "Δεν έχουν επιλεγεί αρχεία.",
        'prompt_delete': "Θέλετε να διαγραφούν τα αρχικά αρχεία μετά την επιτυχή επεξεργασία;",
        'title_delete': "Διαγραφή Αρχείων;",
        'title_done': "GKrypt",
        'msg_done': "Ολοκληρώθηκε.\n\nΕπιτυχία:\n",
        'msg_errors': "\n\nΣφάλματα:\n",
        'msg_dnd': "Εγκαταστήστε το tkinterdnd2 για υποστήριξη μεταφοράς και απόθεσης.",
        'language': "Γλώσσα:",
        'about_text': "GKrypt v{}\n\nΔημιουργήθηκε από τον GK\nΚρυπτογράφηση AES-256-GCM\n© 2025",
        'invalid_format': "Το αρχείο δεν είναι κρυπτογραφημένο από το GKrypt.",
    }
}
class GKryptGUI:
    def __init__(self, root):
        self.root = root
        self.lang = 'en'
        root.title("GKrypt")
        root.configure(bg="#1e1e1e")
        if os.path.exists(ICON_FILE):
            root.iconbitmap(ICON_FILE)

        self.file_paths = []
        self.password = tk.StringVar()
        self.password_confirm = tk.StringVar()
        self.output_folder = tk.StringVar()
        self.mode = tk.StringVar(value="encrypt")

        self.label_opts = {"bg": "#1e1e1e", "fg": "#ffffff"}
        self.entry_opts = {"bg": "#2e2e2e", "fg": "#ffffff", "insertbackground": "#ffffff"}
        self.button_opts = {"bg": "#3e3e3e", "fg": "#ffffff", "activebackground": "#5e5e5e"}

        self.widgets = {}

        menubar = Menu(root)
        helpmenu = Menu(menubar, tearoff=0)
        helpmenu.add_command(label=T[self.lang]['about'], command=self.show_about)
        menubar.add_cascade(label="Help", menu=helpmenu)
        root.config(menu=menubar)

        self.show_splash()

        tk.Label(root, text=T[self.lang]['language'], **self.label_opts).grid(row=0, column=0, sticky="w")
        tk.Button(root, text="EN", command=lambda: self.set_language('en'), **self.button_opts, width=4).grid(row=0, column=1, sticky="w")
        tk.Button(root, text="GR", command=lambda: self.set_language('gr'), **self.button_opts, width=4).grid(row=0, column=1)

        self.widgets['file_label'] = tk.Label(root, text=T[self.lang]['selected_files'], **self.label_opts)
        self.widgets['file_label'].grid(row=1, column=0, sticky="nw")
        self.file_listbox = tk.Listbox(root, width=60, height=8, bg="#2e2e2e", fg="#ffffff")
        self.file_listbox.grid(row=1, column=1, padx=5, pady=5)

        if DND_AVAILABLE:
            self.file_listbox.drop_target_register(DND_FILES)
            self.file_listbox.dnd_bind("<<Drop>>", self.drop_files)

        self.widgets['browse'] = tk.Button(root, text=T[self.lang]['browse'], command=self.browse_files, **self.button_opts)
        self.widgets['browse'].grid(row=1, column=2, padx=5)

        self.widgets['pw_label'] = tk.Label(root, text=T[self.lang]['password'], **self.label_opts)
        self.widgets['pw_label'].grid(row=2, column=0, sticky="e")
        tk.Entry(root, textvariable=self.password, show="*", width=50, **self.entry_opts).grid(row=2, column=1, padx=5, pady=2)

        self.widgets['pw_confirm_label'] = tk.Label(root, text=T[self.lang]['confirm_password'], **self.label_opts)
        self.widgets['pw_confirm_label'].grid(row=3, column=0, sticky="e")
        tk.Entry(root, textvariable=self.password_confirm, show="*", width=50, **self.entry_opts).grid(row=3, column=1, padx=5, pady=2)

        self.widgets['out_label'] = tk.Label(root, text=T[self.lang]['output_folder'], **self.label_opts)
        self.widgets['out_label'].grid(row=4, column=0, sticky="e")
        tk.Entry(root, textvariable=self.output_folder, width=50, **self.entry_opts).grid(row=4, column=1, padx=5, pady=2)
        self.widgets['select'] = tk.Button(root, text=T[self.lang]['select'], command=self.select_output_folder, **self.button_opts)
        self.widgets['select'].grid(row=4, column=2, padx=5)

        self.widgets['encrypt'] = tk.Radiobutton(root, text=T[self.lang]['encrypt'], variable=self.mode, value="encrypt", **self.label_opts, selectcolor="#1e1e1e")
        self.widgets['encrypt'].grid(row=5, column=1, sticky="w", padx=5)
        self.widgets['decrypt'] = tk.Radiobutton(root, text=T[self.lang]['decrypt'], variable=self.mode, value="decrypt", **self.label_opts, selectcolor="#1e1e1e")
        self.widgets['decrypt'].grid(row=5, column=1, sticky="e", padx=5)

        self.widgets['run'] = tk.Button(root, text=T[self.lang]['run'], command=self.run, **self.button_opts)
        self.widgets['run'].grid(row=6, column=1, pady=10)
        self.widgets['view_log'] = tk.Button(root, text=T[self.lang]['view_log'], command=self.view_log, **self.button_opts)
        self.widgets['view_log'].grid(row=6, column=2, pady=10)

    def show_splash(self):
        self.root.deiconify()
    def show_about(self):
        messagebox.showinfo("About GKrypt", T[self.lang]['about_text'].format(VERSION))

    def get_log_path(self):
        if not os.path.exists(LOG_DIR):
            os.makedirs(LOG_DIR)
        today = datetime.now().strftime("%Y-%m-%d")
        return os.path.join(LOG_DIR, f"gkrypt_{today}.log")

    def log_action(self, message):
        log_path = self.get_log_path()
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        if os.path.exists(log_path) and os.path.getsize(log_path) > MAX_LOG_SIZE:
            with open(log_path, "w", encoding="utf-8") as log:
                log.write(f"{timestamp} Log reset due to size limit.\n")
        with open(log_path, "a", encoding="utf-8") as log:
            log.write(f"{timestamp} {message}\n")

    def view_log(self):
        log_path = self.get_log_path()
        if not os.path.exists(log_path):
            messagebox.showinfo("GKrypt", "No log file found.")
            return
        win = Toplevel(self.root)
        win.title("GKrypt Log Viewer")
        win.geometry("700x500")
        text = scrolledtext.ScrolledText(win, wrap="word", bg="#1e1e1e", fg="#ffffff")
        text.pack(fill="both", expand=True)
        with open(log_path, "r", encoding="utf-8") as f:
            content = f.read()
            text.insert("1.0", content)
        text.config(state="disabled")

    def browse_files(self):
        filenames = filedialog.askopenfilenames()
        if filenames:
            self.add_files(filenames)

    def drop_files(self, event):
        files = self.root.tk.splitlist(event.data)
        self.add_files(files)

    def add_files(self, files):
        self.file_paths.extend(files)
        self.file_paths = list(dict.fromkeys(self.file_paths))
        self.refresh_listbox()

    def refresh_listbox(self):
        self.file_listbox.delete(0, tk.END)
        for f in self.file_paths:
            self.file_listbox.insert(tk.END, f)

    def select_output_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.output_folder.set(folder)

    def is_strong_password(self, pwd):
        return all([
            len(pwd) >= 8,
            re.search(r"[A-Z]", pwd),
            re.search(r"[a-z]", pwd),
            re.search(r"[0-9]", pwd),
            re.search(r"[^A-Za-z0-9]", pwd)
        ])

    def set_language(self, lang):
        self.lang = lang
        self.refresh_labels()

    def refresh_labels(self):
        self.widgets['file_label'].config(text=T[self.lang]['selected_files'])
        self.widgets['browse'].config(text=T[self.lang]['browse'])
        self.widgets['pw_label'].config(text=T[self.lang]['password'])
        self.widgets['pw_confirm_label'].config(text=T[self.lang]['confirm_password'])
        self.widgets['out_label'].config(text=T[self.lang]['output_folder'])
        self.widgets['select'].config(text=T[self.lang]['select'])
        self.widgets['encrypt'].config(text=T[self.lang]['encrypt'])
        self.widgets['decrypt'].config(text=T[self.lang]['decrypt'])
        self.widgets['run'].config(text=T[self.lang]['run'])
        self.widgets['view_log'].config(text=T[self.lang]['view_log'])
    def run(self):
        mode = self.mode.get()
        password = self.password.get()
        confirm = self.password_confirm.get()
        out_folder = self.output_folder.get()

        if mode == "encrypt":
            if password != confirm:
                messagebox.showerror("Error", T[self.lang]['error_pw_match'])
                return
            if not self.is_strong_password(password):
                messagebox.showwarning("Weak Password", T[self.lang]['error_pw_strength'])
                return

        if not self.file_paths:
            messagebox.showwarning("Warning", T[self.lang]['warning_no_files'])
            return

        ask_delete = messagebox.askyesno(T[self.lang]['title_delete'], T[self.lang]['prompt_delete'])
        success = []
        failed = []

        for path in self.file_paths:
            try:
                filename = os.path.basename(path)
                output_path = os.path.join(out_folder, filename + (".gkenc" if mode == "encrypt" else ".decrypted")) if out_folder else None

                if mode == "encrypt":
                    result = encrypt_file(path, password, output_path)
                    self.log_action(f"ENCRYPT OK: {path} → {result}")
                else:
                    result = decrypt_file(path, password, output_path)
                    self.log_action(f"DECRYPT OK: {path} → {result}")

                success.append(result)
                if ask_delete:
                    os.remove(path)
                    self.log_action(f"DELETE: {path}")

            except WrongPasswordError:
                messagebox.showerror("GKrypt", f"🔒 Λάθος κωδικός.\n\n{path}" if self.lang == "gr" else f"🔒 Wrong password.\n\n{path}")
                self.log_action(f"DECRYPT FAIL (wrong password): {path}")

            except CorruptedFileError:
                messagebox.showerror("GKrypt", f"⚠️ Το αρχείο είναι αλλοιωμένο ή ημιτελές.\n\n{path}" if self.lang == "gr" else f"⚠️ The file appears to be corrupted or incomplete.\n\n{path}")
                self.log_action(f"DECRYPT FAIL (corrupted): {path}")

            except Exception as e:
                err_msg = str(e)
                if "Invalid file format" in err_msg:
                    messagebox.showerror("GKrypt", f"{T[self.lang]['invalid_format']}\n\n{path}")
                elif "Unsupported GKrypt version" in err_msg:
                    messagebox.showerror("GKrypt", f"❗ Το αρχείο είναι σε μη υποστηριζόμενη έκδοση του GKrypt.\n\n{path}" if self.lang == "gr" else f"❗ The file uses an unsupported GKrypt version.\n\n{path}")
                else:
                    failed.append(f"{path}: {err_msg}")
                self.log_action(f"{mode.upper()} FAIL: {path} → {err_msg}")

        summary = T[self.lang]['msg_done'] + "\n".join(success)
        if failed:
            summary += T[self.lang]['msg_errors'] + "\n".join(failed)
        messagebox.showinfo(T[self.lang]['title_done'], summary)

        self.file_paths.clear()
        self.refresh_listbox()


if __name__ == '__main__':
    if DND_AVAILABLE:
        from tkinterdnd2 import TkinterDnD
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()
        messagebox.showwarning("Drag and Drop Disabled", T['en']['msg_dnd'])

    app = GKryptGUI(root)
    root.mainloop()
