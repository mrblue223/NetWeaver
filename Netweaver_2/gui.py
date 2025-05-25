import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from PIL import Image, ImageTk
import threading
import time
import os

import constants
from server_core import _server_main_loop, stop_server

class TCPServerGUI:
    """
    A Tkinter-based GUI for a multi-threaded TCP/Web/FTP server.
    Designed with a modern, dark theme.
    """

    def __init__(self, master):
        """
        Initializes the TCPServerGUI.

        Args:
            master (tk.Tk): The root Tkinter window.
        """
        self.master = master
        master.title("NetWeaver - Server GUI")
        master.geometry("1000x700")
        master.resizable(True, True)

        # Set the window icon
        try:
            icon_image = Image.open("assets/icons8-server-40.png")
            self.app_icon = ImageTk.PhotoImage(icon_image)
            master.iconphoto(False, self.app_icon)
        except FileNotFoundError:
            self.log_message(
                "[-] Application icon (icons8-server-40.png) not found.",
                'warning'
            )
        except Exception as e:
            self.log_message(
                f"[-] Error loading application icon: {e}", 'error'
            )

        # --- Configure Modern Dark Theme ---
        self.master.tk_setPalette(background=constants.BG_DARK_PRIMARY,
                                  foreground=constants.TEXT_COLOR,
                                  activeBackground=constants.ACCENT_BLUE_HOVER,
                                  activeForeground=constants.BUTTON_TEXT_COLOR)

        style = ttk.Style()
        style.theme_use('clam')

        # General styles for Frames
        style.configure('TFrame', background=constants.BG_DARK_SECONDARY)
        style.configure(
            'DarkFrame.TFrame', background=constants.BG_DARK_PRIMARY
        )

        # Label styles
        style.configure(
            'TLabel', background=constants.BG_DARK_SECONDARY,
            foreground=constants.TEXT_COLOR, font=('Segoe UI', 10)
        )
        style.configure(
            'Header.TLabel', background=constants.BG_DARK_PRIMARY,
            foreground=constants.ACCENT_BLUE, font=('Segoe UI', 14, 'bold')
        )
        style.configure(
            'Sidebar.TLabel', background=constants.BG_DARK_PRIMARY,
            foreground=constants.TEXT_COLOR, font=('Segoe UI', 10)
        )

        # Entry field styles
        style.configure(
            'TEntry', fieldbackground=constants.BG_DARK_TERTIARY,
            foreground=constants.TEXT_COLOR, borderwidth=1, relief='flat',
            font=('Segoe UI', 10), bordercolor=constants.BORDER_COLOR
        )
        style.map('TEntry', fieldbackground=[('disabled', constants.DISABLED_COLOR)])

        # Button styles (generic)
        style.configure(
            'TButton', background=constants.ACCENT_BLUE,
            foreground=constants.BUTTON_TEXT_COLOR, font=('Segoe UI', 10, 'bold'),
            borderwidth=0, relief='flat', padding=[12, 6]
        )
        style.map(
            'TButton',
            background=[('active', constants.ACCENT_BLUE_HOVER),
                        ('disabled', constants.DISABLED_COLOR)],
            foreground=[('disabled', constants.TEXT_COLOR)]
        )

        # Sidebar button style (flat, with hover, and a selected state)
        style.configure(
            'Sidebar.TButton', background=constants.BG_DARK_PRIMARY,
            foreground=constants.TEXT_COLOR, font=('Segoe UI', 10), borderwidth=0,
            relief='flat', padding=[15, 10], focusthickness=0,
            highlightthickness=0
        )
        style.map(
            'Sidebar.TButton',
            background=[('active', constants.ACCENT_BLUE_HOVER),
                        ('selected', constants.ACCENT_BLUE)],
            foreground=[('active', constants.BUTTON_TEXT_COLOR),
                        ('selected', constants.BUTTON_TEXT_COLOR),
                        ('disabled', constants.TEXT_COLOR)]
        )

        # Radiobutton styles (though not used directly, good to have if needed)
        style.configure(
            'TRadiobutton', background=constants.BG_DARK_SECONDARY,
            foreground=constants.TEXT_COLOR, font=('Segoe UI', 10),
            indicatoron=False, padding=[10, 5], relief='flat',
            borderwidth=1, bordercolor=constants.BORDER_COLOR, focusthickness=0
        )
        style.map(
            'TRadiobutton',
            background=[('active', constants.ACCENT_BLUE_HOVER),
                        ('selected', constants.ACCENT_BLUE),
                        ('!selected', constants.BG_DARK_SECONDARY)],
            foreground=[('active', constants.BUTTON_TEXT_COLOR),
                        ('selected', constants.BUTTON_TEXT_COLOR),
                        ('!selected', constants.TEXT_COLOR)],
            bordercolor=[('selected', constants.ACCENT_BLUE)],
            relief=[('selected', 'flat'), ('!selected', 'solid')]
        )

        # ScrolledText (Log) styles
        style.configure(
            'TScrolledtext', background=constants.BG_DARK_TERTIARY,
            foreground=constants.TEXT_COLOR, font=('Consolas', 9),
            insertbackground=constants.TEXT_COLOR, selectbackground=constants.ACCENT_BLUE,
            selectforeground='white', borderwidth=1, relief='flat',
            bordercolor=constants.BORDER_COLOR
        )

        # Scrollbar style
        style.configure(
            "Vertical.TScrollbar", troughcolor=constants.BG_DARK_SECONDARY,
            background=constants.BORDER_COLOR, gripcount=0,
            bordercolor=constants.BORDER_COLOR, darkcolor=constants.BORDER_COLOR,
            lightcolor=constants.BORDER_COLOR, arrowsize=0, relief='flat'
        )
        style.map(
            "Vertical.TScrollbar",
            background=[('active', constants.ACCENT_BLUE_HOVER),
                        ('!active', constants.BORDER_COLOR)]
        )

        self.log_text_scroll_style = "Vertical.TScrollbar"

        self.server_thread = None
        self.server_mode_var = tk.StringVar(value="tcp")
        self.current_sidebar_mode_button = None

        # --- Main Layout ---
        self.master.grid_rowconfigure(0, weight=1)
        self.master.grid_columnconfigure(0, weight=0)
        self.master.grid_columnconfigure(1, weight=1)

        # --- Sidebar Frame ---
        self.sidebar_frame = ttk.Frame(
            master, style='DarkFrame.TFrame', padding="10 10 10 10"
        )
        self.sidebar_frame.grid(row=0, column=0, sticky="nswe")
        self.sidebar_frame.grid_rowconfigure(9, weight=1)

        # Load and display the server icon
        try:
            self.server_icon_image = Image.open("assets/icons8-server-40.png")
            self.server_icon_photo = ImageTk.PhotoImage(self.server_icon_image)
            self.icon_label = ttk.Label(
                self.sidebar_frame, image=self.server_icon_photo,
                background=constants.BG_DARK_PRIMARY
            )
            self.icon_label.pack(pady=5, padx=10, anchor='w')
        except FileNotFoundError:
            self.log_message(
                "[-] Server icon (icons8-server-40.png) not found.",
                'warning'
            )
            self.server_icon_photo = None
        except Exception as e:
            self.log_message(f"[-] Error loading server icon: {e}", 'error')
            self.server_icon_photo = None

        # Sidebar Header
        ttk.Label(
            self.sidebar_frame, text="< NetWeaver", style='Header.TLabel',
            anchor='w'
        ).pack(pady=5, padx=10, fill=tk.X)

        # New Sidebar Buttons: Server Controls
        self.sidebar_start_button = ttk.Button(
            self.sidebar_frame, text="  < Start Server",
            style='Sidebar.TButton', command=self.start_server_gui
        )
        self.sidebar_start_button.pack(fill=tk.X, pady=2, padx=5)

        self.sidebar_stop_button = ttk.Button(
            self.sidebar_frame, text="  < Stop Server",
            style='Sidebar.TButton', command=self.stop_server_gui,
            state=tk.DISABLED
        )
        self.sidebar_stop_button.pack(fill=tk.X, pady=2, padx=5)

        self.sidebar_status_button = ttk.Button(
            self.sidebar_frame, text="  < Server Status",
            style='Sidebar.TButton', command=self.show_server_status
        )
        self.sidebar_status_button.pack(fill=tk.X, pady=2, padx=5)

        ttk.Label(
            self.sidebar_frame, text="", background=constants.BG_DARK_PRIMARY
        ).pack(pady=10, fill=tk.X)

        # New Sidebar Buttons: Mode Selection
        self.sidebar_tcp_mode_button = ttk.Button(
            self.sidebar_frame, text="  < Generic TCP",
            style='Sidebar.TButton', command=lambda: self.set_server_mode("tcp")
        )
        self.sidebar_tcp_mode_button.pack(fill=tk.X, pady=2, padx=5)

        self.sidebar_web_http_mode_button = ttk.Button(
            self.sidebar_frame, text="  < Web Server (HTTP)",
            style='Sidebar.TButton', command=lambda: self.set_server_mode("web")
        )
        self.sidebar_web_http_mode_button.pack(fill=tk.X, pady=2, padx=5)

        self.sidebar_web_https_mode_button = ttk.Button(
            self.sidebar_frame, text="  < Web Server (HTTPS)",
            style='Sidebar.TButton',
            command=lambda: self.set_server_mode("https")
        )
        self.sidebar_web_https_mode_button.pack(fill=tk.X, pady=2, padx=5)

        self.sidebar_ftp_mode_button = ttk.Button(
            self.sidebar_frame, text="  < FTP Server",
            style='Sidebar.TButton', command=lambda: self.set_server_mode("ftp")
        )
        self.sidebar_ftp_mode_button.pack(fill=tk.X, pady=2, padx=5)

        # Bottom sidebar buttons (spacer needed to push to bottom)
        ttk.Label(
            self.sidebar_frame, text="", background=constants.BG_DARK_PRIMARY
        ).pack(expand=True, fill=tk.BOTH)

        # --- Main Content Frame ---
        self.main_content_frame = ttk.Frame(
            master, style='DarkFrame.TFrame', padding="20 20 20 20"
        )
        self.main_content_frame.grid(row=0, column=1, sticky="nswe")
        self.main_content_frame.grid_rowconfigure(0, weight=0)
        self.main_content_frame.grid_rowconfigure(1, weight=0)
        self.main_content_frame.grid_rowconfigure(2, weight=1)
        self.main_content_frame.grid_columnconfigure(0, weight=1)

        # Main content header
        ttk.Label(
            self.main_content_frame, text="Multi-threaded TCP/Web/FTP Server",
            style='Header.TLabel', anchor='center'
        ).grid(row=0, column=0, pady=15, sticky=tk.N + tk.S + tk.E + tk.W)

        # --- Control Frame (nested within main_content_frame) ---
        self.control_frame = ttk.Frame(
            self.main_content_frame, padding="15 15 15 15", relief="flat"
        )
        self.control_frame.grid(
            row=1, column=0, padx=15, pady=15, sticky=tk.N + tk.S + tk.E + tk.W
        )

        # Configure columns for control_frame
        self.control_frame.grid_columnconfigure(0, weight=0)
        self.control_frame.grid_columnconfigure(1, weight=1)
        self.control_frame.grid_columnconfigure(2, weight=0)

        # Server Port
        self.port_label = ttk.Label(self.control_frame, text="Server Port:")
        self.port_label.grid(row=0, column=0, padx=10, pady=8, sticky=tk.W)
        self.port_entry = ttk.Entry(self.control_frame)
        self.port_entry.insert(0, "9999")
        self.port_entry.grid(row=0, column=1, padx=10, pady=8, sticky=tk.W + tk.E)

        # Web Root Directory Input
        self.web_root_label = ttk.Label(self.control_frame, text="Web Root Dir:")
        self.web_root_path_var = tk.StringVar(value=constants.WEB_ROOT_DIR)
        self.web_root_entry = ttk.Entry(
            self.control_frame, textvariable=self.web_root_path_var
        )
        self.browse_web_button = ttk.Button(
            self.control_frame, text="Browse...", command=self.browse_web_root
        )

        # FTP Root Directory Input
        self.ftp_root_label = ttk.Label(self.control_frame, text="FTP Root Dir:")
        self.ftp_root_path_var = tk.StringVar(value=constants.FTP_ROOT_DIR)
        self.ftp_root_entry = ttk.Entry(
            self.control_frame, textvariable=self.ftp_root_path_var
        )
        self.browse_ftp_button = ttk.Button(
            self.control_frame, text="Browse...", command=self.browse_ftp_root
        )

        # SSL Certificate File Input
        self.ssl_cert_label = ttk.Label(
            self.control_frame, text="SSL Cert File:"
        )
        self.ssl_cert_path_var = tk.StringVar(value=constants.SSL_CERT_FILE)
        self.ssl_cert_entry = ttk.Entry(
            self.control_frame, textvariable=self.ssl_cert_path_var
        )
        self.browse_ssl_cert_button = ttk.Button(
            self.control_frame, text="Browse...", command=self.browse_ssl_cert
        )

        # SSL Key File Input
        self.ssl_key_label = ttk.Label(self.control_frame, text="SSL Key File:")
        self.ssl_key_path_var = tk.StringVar(value=constants.SSL_KEY_FILE)
        self.ssl_key_entry = ttk.Entry(
            self.control_frame, textvariable=self.ssl_key_path_var
        )
        self.browse_ssl_key_button = ttk.Button(
            self.control_frame, text="Browse...", command=self.browse_ssl_key
        )

        # --- Log Frame (nested within main_content_frame) ---
        self.log_frame = ttk.Frame(
            self.main_content_frame, padding="15 15 15 15", relief="flat"
        )
        self.log_frame.grid(
            row=2, column=0, padx=15, pady=15, sticky=tk.N + tk.S + tk.E + tk.W
        )
        self.log_frame.grid_rowconfigure(0, weight=1)
        self.log_frame.grid_columnconfigure(0, weight=1)

        self.log_text = scrolledtext.ScrolledText(
            self.log_frame, wrap=tk.WORD, state=tk.DISABLED,
            yscrollcommand=lambda *args: self.log_text.tk.call(
                'set', self.log_text_scroll_style, *args
            )
        )
        self.log_text.grid(row=0, column=0, sticky=tk.N + tk.S + tk.E + tk.W)

        # Configure log message tags for different colors
        self.log_text.tag_config('info', foreground=constants.ACCENT_BLUE)
        self.log_text.tag_config('success', foreground='#4CAF50')
        self.log_text.tag_config('error', foreground='#ff6b6b')
        self.log_text.tag_config('warning', foreground='#ffc107')

        # Set initial mode and update UI
        self.set_server_mode("tcp")

        master.protocol("WM_DELETE_WINDOW", self.on_closing)

    def set_server_mode(self, mode):
        """
        Sets the server mode and updates the UI accordingly.

        Args:
            mode (str): The desired server mode ("tcp", "web", "https", "ftp").
        """
        if constants.SERVER_RUNNING:
            self.log_message(
                "[-] Cannot change server mode while server is running. "
                "Stop the server first.", 'warning'
            )
            return

        self.server_mode_var.set(mode)
        constants.SERVER_MODE = mode # Update global constant
        self.log_message(f"[*] Server Mode set to: {mode.upper()}", 'info')
        self.toggle_mode_inputs()
        self.update_sidebar_mode_button_highlight(mode)

    def update_sidebar_mode_button_highlight(self, selected_mode):
        """
        Highlights the currently selected mode button in the sidebar.

        Args:
            selected_mode (str): The mode that is currently selected.
        """
        mode_buttons = {
            "tcp": self.sidebar_tcp_mode_button,
            "web": self.sidebar_web_http_mode_button,
            "https": self.sidebar_web_https_mode_button,
            "ftp": self.sidebar_ftp_mode_button,
        }

        for mode, button in mode_buttons.items():
            if mode == selected_mode:
                button.state(['selected'])
            else:
                button.state(['!selected'])

    def show_server_status(self):
        """Displays the current server status in the log."""
        status_message = "[*] Server Status: "
        if constants.SERVER_RUNNING:
            try:
                server_ip, server_port = constants.SERVER_SOCKET.getsockname()
                status_message += f"RUNNING on {server_ip}:{server_port}\n"
                status_message += f"[*] Current Mode: {constants.SERVER_MODE.upper()}\n"
                if constants.SERVER_MODE == "web" or constants.SERVER_MODE == "https":
                    status_message += f"[*] Web Root: {constants.WEB_ROOT_DIR}\n"
                    if constants.SERVER_MODE == "https":
                        status_message += f"[*] SSL Cert: {constants.SSL_CERT_FILE}\n"
                        status_message += f"[*] SSL Key: {constants.SSL_KEY_FILE}\n"
                elif constants.SERVER_MODE == "ftp":
                    status_message += f"[*] FTP Root: {constants.FTP_ROOT_DIR}\n"
                self.log_message(status_message, 'success')
            except Exception:
                self.log_message(
                    f"[-] Server is running, but socket info unavailable. "
                    f"Check log for errors.", 'warning'
                )
        else:
            status_message += "STOPPED\n"
            self.log_message(status_message, 'error')

    def toggle_mode_inputs(self):
        """
        Shows or hides the web/ftp root directory and SSL inputs based on the
        selected server mode.
        """
        current_mode = self.server_mode_var.get()

        # Hide all root/SSL inputs first
        self.web_root_label.grid_forget()
        self.web_root_entry.grid_forget()
        self.browse_web_button.grid_forget()
        self.ftp_root_label.grid_forget()
        self.ftp_root_entry.grid_forget()
        self.browse_ftp_button.grid_forget()
        self.ssl_cert_label.grid_forget()
        self.ssl_cert_entry.grid_forget()
        self.browse_ssl_cert_button.grid_forget()
        self.ssl_key_label.grid_forget()
        self.ssl_key_entry.grid_forget()
        self.browse_ssl_key_button.grid_forget()

        # Place root inputs based on selected mode
        if current_mode == "web":
            self.web_root_label.grid(row=1, column=0, padx=10, pady=8,
                                     sticky=tk.W)
            self.web_root_entry.grid(row=1, column=1, padx=10, pady=8,
                                     sticky=tk.W + tk.E)
            self.browse_web_button.grid(row=1, column=2, padx=10, pady=8,
                                        sticky=tk.W)
        elif current_mode == "https":
            self.web_root_label.grid(row=1, column=0, padx=10, pady=8,
                                     sticky=tk.W)
            self.web_root_entry.grid(row=1, column=1, padx=10, pady=8,
                                     sticky=tk.W + tk.E)
            self.browse_web_button.grid(row=1, column=2, padx=10, pady=8,
                                        sticky=tk.W)

            self.ssl_cert_label.grid(row=2, column=0, padx=10, pady=8,
                                     sticky=tk.W)
            self.ssl_cert_entry.grid(row=2, column=1, padx=10, pady=8,
                                     sticky=tk.W + tk.E)
            self.browse_ssl_cert_button.grid(row=2, column=2, padx=10, pady=8,
                                             sticky=tk.W)

            self.ssl_key_label.grid(row=3, column=0, padx=10, pady=8,
                                    sticky=tk.W)
            self.ssl_key_entry.grid(row=3, column=1, padx=10, pady=8,
                                    sticky=tk.W + tk.E)
            self.browse_ssl_key_button.grid(row=3, column=2, padx=10, pady=8,
                                            sticky=tk.W)

        elif current_mode == "ftp":
            self.ftp_root_label.grid(row=1, column=0, padx=10, pady=8,
                                     sticky=tk.W)
            self.ftp_root_entry.grid(row=1, column=1, padx=10, pady=8,
                                     sticky=tk.W + tk.E)
            self.browse_ftp_button.grid(row=1, column=2, padx=10, pady=8,
                                        sticky=tk.W)

        # Adjust states based on SERVER_RUNNING
        self.update_button_states()

    def browse_web_root(self):
        """Opens a directory selection dialog for the web root."""
        directory = filedialog.askdirectory()
        if directory:
            self.web_root_path_var.set(directory)

    def browse_ftp_root(self):
        """Opens a directory selection dialog for the FTP root."""
        directory = filedialog.askdirectory()
        if directory:
            self.ftp_root_path_var.set(directory)

    def browse_ssl_cert(self):
        """Opens a file selection dialog for the SSL certificate file."""
        filepath = filedialog.askopenfilename(
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        if filepath:
            self.ssl_cert_path_var.set(filepath)

    def browse_ssl_key(self):
        """Opens a file selection dialog for the SSL key file."""
        filepath = filedialog.askopenfilename(
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        if filepath:
            self.ssl_key_path_var.set(filepath)

    def log_message(self, message, tag=None):
        """
        Appends a message to the log text area in a thread-safe manner with
        optional tag for coloring.

        Args:
            message (str): The message to log.
            tag (str, optional): A tag for coloring the message (e.g., 'info',
                                 'success', 'error', 'warning').
                                 Defaults to None.
        """
        self.master.after(0, self._append_log, message, tag)

    def _append_log(self, message, tag):
        """
        Internal method to append message to log_text.
        This method is called via `master.after` to ensure it runs on the
        main Tkinter thread.

        Args:
            message (str): The message to append.
            tag (str): The tag for coloring.
        """
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n", tag)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def start_server_gui(self):
        """
        Initiates the server startup process based on GUI input.
        Performs input validation and starts the server in a new thread.
        """
        if constants.SERVER_RUNNING:
            self.log_message("[*] Server is already running.", 'warning')
            return

        try:
            port = int(self.port_entry.get())
            if not (1 <= port <= 65535):
                messagebox.showerror(
                    "Invalid Port", "Port number must be between 1 and 65535."
                )
                return
        except ValueError:
            messagebox.showerror(
                "Invalid Port", "Please enter a valid integer for the port."
            )
            return

        current_mode = self.server_mode_var.get()

        # Update global constants before starting the server thread
        constants.WEB_ROOT_DIR = self.web_root_path_var.get()
        constants.FTP_ROOT_DIR = self.ftp_root_path_var.get()
        constants.SSL_CERT_FILE = self.ssl_cert_path_var.get()
        constants.SSL_KEY_FILE = self.ssl_key_path_var.get()

        if current_mode == "web" or current_mode == "https":
            if not constants.WEB_ROOT_DIR or not os.path.isdir(constants.WEB_ROOT_DIR):
                messagebox.showerror(
                    "Invalid Web Root",
                    "Please select a valid web root directory for Web Server "
                    "mode."
                )
                return
            if current_mode == "https":
                if not constants.SSL_CERT_FILE or not os.path.isfile(constants.SSL_CERT_FILE):
                    messagebox.showerror(
                        "Invalid SSL Certificate",
                        "Please select a valid SSL certificate file (.pem) "
                        "for HTTPS mode."
                    )
                    return
                if not constants.SSL_KEY_FILE or not os.path.isfile(constants.SSL_KEY_FILE):
                    messagebox.showerror(
                        "Invalid SSL Key",
                        "Please select a valid SSL key file (.pem) for HTTPS "
                        "mode."
                    )
                    return

        elif current_mode == "ftp":
            if not constants.FTP_ROOT_DIR or not os.path.isdir(constants.FTP_ROOT_DIR):
                messagebox.showerror(
                    "Invalid FTP Root",
                    "Please select a valid FTP root directory for FTP Server "
                    "mode."
                )
                return

        self.log_message(
            f"[*] Attempting to start server on port {port} in "
            f"{current_mode.upper()} mode...", 'info'
        )

        self.server_thread = threading.Thread(
            target=_server_main_loop,
            args=(port, self.log_message, self.update_button_states,
                  current_mode, constants.WEB_ROOT_DIR, constants.FTP_ROOT_DIR,
                  constants.SSL_CERT_FILE, constants.SSL_KEY_FILE)
        )
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop_server_gui(self):
        """
        Calls the centralized stop_server function.
        """
        stop_server(self.log_message, self.update_button_states)

    def update_button_states(self, starting=False):
        """
        Updates the state of the Start/Stop buttons (now in sidebar) and input
        fields based on server status.

        Args:
            starting (bool, optional): True if the server is in the process
                                       of starting. Defaults to False.
        """
        mode_buttons = [
            self.sidebar_tcp_mode_button,
            self.sidebar_web_http_mode_button,
            self.sidebar_web_https_mode_button,
            self.sidebar_ftp_mode_button
        ]

        if constants.SERVER_RUNNING:
            self.sidebar_start_button.config(state=tk.DISABLED)
            self.sidebar_stop_button.config(state=tk.NORMAL)
            self.sidebar_status_button.config(state=tk.NORMAL)

            self.port_entry.config(state=tk.DISABLED)

            for btn in mode_buttons:
                btn.config(state=tk.DISABLED)

            self.web_root_entry.config(state=tk.DISABLED)
            self.browse_web_button.config(state=tk.DISABLED)
            self.ftp_root_entry.config(state=tk.DISABLED)
            self.browse_ftp_button.config(state=tk.DISABLED)
            self.ssl_cert_entry.config(state=tk.DISABLED)
            self.browse_ssl_cert_button.config(state=tk.DISABLED)
            self.ssl_key_entry.config(state=tk.DISABLED)
            self.browse_ssl_key_button.config(state=tk.DISABLED)
        else:
            self.sidebar_start_button.config(state=tk.NORMAL)
            self.sidebar_stop_button.config(state=tk.DISABLED)
            self.sidebar_status_button.config(state=tk.NORMAL)

            self.port_entry.config(state=tk.NORMAL)

            for btn in mode_buttons:
                btn.config(state=tk.NORMAL)

            current_mode = self.server_mode_var.get()
            if current_mode == "web":
                self.web_root_entry.config(state=tk.NORMAL)
                self.browse_web_button.config(state=tk.NORMAL)
                self.ftp_root_entry.config(state=tk.DISABLED)
                self.browse_ftp_button.config(state=tk.DISABLED)
                self.ssl_cert_entry.config(state=tk.DISABLED)
                self.browse_ssl_cert_button.config(state=tk.DISABLED)
                self.ssl_key_entry.config(state=tk.DISABLED)
                self.browse_ssl_key_button.config(state=tk.DISABLED)
            elif current_mode == "https":
                self.web_root_entry.config(state=tk.NORMAL)
                self.browse_web_button.config(state=tk.NORMAL)
                self.ssl_cert_entry.config(state=tk.NORMAL)
                self.browse_ssl_cert_button.config(state=tk.NORMAL)
                self.ssl_key_entry.config(state=tk.NORMAL)
                self.browse_ssl_key_button.config(state=tk.NORMAL)
                self.ftp_root_entry.config(state=tk.DISABLED)
                self.browse_ftp_button.config(state=tk.DISABLED)
            elif current_mode == "ftp":
                self.ftp_root_entry.config(state=tk.NORMAL)
                self.browse_ftp_button.config(state=tk.NORMAL)
                self.web_root_entry.config(state=tk.DISABLED)
                self.browse_web_button.config(state=tk.DISABLED)
                self.ssl_cert_entry.config(state=tk.DISABLED)
                self.browse_ssl_cert_button.config(state=tk.DISABLED)
                self.ssl_key_entry.config(state=tk.DISABLED)
                self.browse_ssl_key_button.config(state=tk.DISABLED)
            else:  # TCP mode
                self.web_root_entry.config(state=tk.DISABLED)
                self.browse_web_button.config(state=tk.DISABLED)
                self.ftp_root_entry.config(state=tk.DISABLED)
                self.browse_ftp_button.config(state=tk.DISABLED)
                self.ssl_cert_entry.config(state=tk.DISABLED)
                self.browse_ssl_cert_button.config(state=tk.DISABLED)
                self.ssl_key_entry.config(state=tk.DISABLED)
                self.browse_ssl_key_button.config(state=tk.DISABLED)

            # Re-apply highlight for the currently selected mode
            self.update_sidebar_mode_button_highlight(self.server_mode_var.get())

            if not starting:
                self.log_message("[*] Server is stopped.", 'info')

    def on_closing(self):
        """
        Handles the window closing event.
        Prompts the user to confirm quitting and stops the server if it's
        running.
        """
        if messagebox.askokcancel("Quit", "Do you want to quit NetWeaver?"):
            self.stop_server_gui()
            # Give a moment for the server thread to potentially clean up
            # This is not foolproof as daemon threads might be terminated abruptly
            time.sleep(0.5)
            self.master.destroy()