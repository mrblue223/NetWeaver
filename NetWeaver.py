import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, filedialog
import socket
import threading
import time
import sys
import os
import mimetypes
import ipaddress
import signal
import ssl # Import the SSL module
from PIL import Image, ImageTk # Import Pillow modules

# Global flags and variables (kept for server functionality)
SERVER_RUNNING = False
server_socket = None
SERVER_MODE = "tcp"
WEB_ROOT_DIR = ""
FTP_ROOT_DIR = ""
SSL_CERT_FILE = "" # New global variable for SSL certificate file
SSL_KEY_FILE = ""  # New global variable for SSL key file

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
        master.title("NetWeaver - Server GUI") # Updated title
        master.geometry("1000x700") # Larger window to accommodate sidebar
        master.resizable(True, True) # Allow resizing

        # Set the window icon
        try:
            icon_image = Image.open("icons8-server-40.png")
            self.app_icon = ImageTk.PhotoImage(icon_image)
            master.iconphoto(False, self.app_icon)
        except FileNotFoundError:
            self.log_message("[-] Application icon (icons8-server-40.png) not found.", 'warning')
        except Exception as e:
            self.log_message(f"[-] Error loading application icon: {e}", 'error')


        # --- Configure Modern Dark Theme ---
        self.bg_dark_primary = '#21252b'  # Main background color (similar to image)
        self.bg_dark_secondary = '#2c313a' # Background for frames/sidebar
        self.bg_dark_tertiary = '#1a1d21' # Darkest for log area
        self.text_color = '#abb2bf'       # Light grey text
        self.accent_blue = '#61afef'      # Primary accent blue
        self.accent_blue_hover = '#528bff' # Darker blue for hover
        self.button_text_color = 'white'  # White for button text
        self.disabled_color = '#4b525d'   # Grey for disabled elements
        self.border_color = '#3e4452'     # Subtle border color

        self.master.tk_setPalette(background=self.bg_dark_primary,
                                  foreground=self.text_color,
                                  activeBackground=self.accent_blue_hover,
                                  activeForeground=self.button_text_color)

        style = ttk.Style()
        style.theme_use('clam') # Good base for customization

        # General styles for Frames
        style.configure('TFrame', background=self.bg_dark_secondary)
        style.configure('DarkFrame.TFrame', background=self.bg_dark_primary) # For the root frame if needed

        # Label styles
        style.configure('TLabel', background=self.bg_dark_secondary, foreground=self.text_color, font=('Segoe UI', 10))
        style.configure('Header.TLabel', background=self.bg_dark_primary, foreground=self.accent_blue, font=('Segoe UI', 14, 'bold'))
        style.configure('Sidebar.TLabel', background=self.bg_dark_primary, foreground=self.text_color, font=('Segoe UI', 10))

        # Entry field styles
        style.configure('TEntry', fieldbackground=self.bg_dark_tertiary, foreground=self.text_color,
                        borderwidth=1, relief='flat', font=('Segoe UI', 10), bordercolor=self.border_color)
        style.map('TEntry', fieldbackground=[('disabled', self.disabled_color)])


        # Button styles (generic)
        style.configure('TButton',
                        background=self.accent_blue,
                        foreground=self.button_text_color,
                        font=('Segoe UI', 10, 'bold'),
                        borderwidth=0,
                        relief='flat',
                        padding=[12, 6]) # Slightly more padding for a modern feel
        style.map('TButton',
                  background=[('active', self.accent_blue_hover), ('disabled', self.disabled_color)],
                  foreground=[('disabled', self.text_color)])

        # Sidebar button style (flat, with hover, and a selected state)
        style.configure('Sidebar.TButton',
                        background=self.bg_dark_primary,
                        foreground=self.text_color,
                        font=('Segoe UI', 10),
                        borderwidth=0,
                        relief='flat',
                        padding=[15, 10],
                        focusthickness=0, # Remove focus border
                        highlightthickness=0) # Remove highlight border
        style.map('Sidebar.TButton',
                  background=[('active', self.accent_blue_hover), ('selected', self.accent_blue)],
                  foreground=[('active', self.button_text_color), ('selected', self.button_text_color), ('disabled', self.text_color)])


        # Radiobutton styles (mimicking the image's flatter design)
        # These are removed from main content, but style might still be referenced if used elsewhere.
        style.configure('TRadiobutton',
                        background=self.bg_dark_secondary,
                        foreground=self.text_color,
                        font=('Segoe UI', 10),
                        indicatoron=False, # Make it a flat button-like radio
                        padding=[10, 5],
                        relief='flat',
                        borderwidth=1,
                        bordercolor=self.border_color,
                        focusthickness=0) # Remove focus border
        style.map('TRadiobutton',
                  background=[('active', self.accent_blue_hover), ('selected', self.accent_blue), ('!selected', self.bg_dark_secondary)],
                  foreground=[('active', self.button_text_color), ('selected', self.button_text_color), ('!selected', self.text_color)],
                  bordercolor=[('selected', self.accent_blue)], # Border becomes accent when selected
                  relief=[('selected', 'flat'), ('!selected', 'solid')]) # Change relief for visual distinction

        # ScrolledText (Log) styles
        style.configure('TScrolledtext',
                        background=self.bg_dark_tertiary,
                        foreground=self.text_color,
                        font=('Consolas', 9), # Monospaced for logs
                        insertbackground=self.text_color,
                        selectbackground=self.accent_blue,
                        selectforeground='white',
                        borderwidth=1,
                        relief='flat',
                        bordercolor=self.border_color)

        # Scrollbar style (modern look)
        style.configure("Vertical.TScrollbar",
                        troughcolor=self.bg_dark_secondary,
                        background=self.border_color, # Default thumb color
                        gripcount=0, # No grip lines
                        bordercolor=self.border_color,
                        darkcolor=self.border_color,
                        lightcolor=self.border_color,
                        arrowsize=0, # No arrow buttons
                        relief='flat')
        style.map("Vertical.TScrollbar",
                  background=[('active', self.accent_blue_hover), # Hover color
                              ('!active', self.border_color)]) # Default color when not active

        # Apply the custom scrollbar style to the ScrolledText widget
        self.log_text_scroll_style = "Vertical.TScrollbar"


        self.server_thread = None
        self.server_mode_var = tk.StringVar(value="tcp") # Keep track of selected mode
        self.current_sidebar_mode_button = None # To track which mode button is 'selected'

        # --- Main Layout (Grid for overall structure) ---
        self.master.grid_rowconfigure(0, weight=1)
        self.master.grid_columnconfigure(0, weight=0) # Sidebar column
        self.master.grid_columnconfigure(1, weight=1) # Main content column

        # --- Sidebar Frame ---
        self.sidebar_frame = ttk.Frame(master, style='DarkFrame.TFrame', padding="10 10 10 10")
        self.sidebar_frame.grid(row=0, column=0, sticky="nswe")
        self.sidebar_frame.grid_rowconfigure(9, weight=1) # Push 'Information' and 'Settings' to bottom

        # Load and display the server icon
        try:
            self.server_icon_image = Image.open("icons8-server-40.png")
            self.server_icon_photo = ImageTk.PhotoImage(self.server_icon_image)
            self.icon_label = ttk.Label(self.sidebar_frame, image=self.server_icon_photo, background=self.bg_dark_primary)
            self.icon_label.pack(pady=5, padx=10, anchor='w') # Adjusted padding and anchor
        except FileNotFoundError:
            self.log_message("[-] Server icon (icons8-server-40.png) not found.", 'warning')
            self.server_icon_photo = None # Ensure it's set to None if file not found
        except Exception as e:
            self.log_message(f"[-] Error loading server icon: {e}", 'error')
            self.server_icon_photo = None

        # Sidebar Header (modified to be alongside or below the icon)
        ttk.Label(self.sidebar_frame, text="< NetWeaver", style='Header.TLabel', anchor='w').pack(pady=5, padx=10, fill=tk.X) # Reduced pady


        # New Sidebar Buttons: Server Controls
        self.sidebar_start_button = ttk.Button(self.sidebar_frame, text="  < Start Server", style='Sidebar.TButton', command=self.start_server_gui)
        self.sidebar_start_button.pack(fill=tk.X, pady=2, padx=5)

        self.sidebar_stop_button = ttk.Button(self.sidebar_frame, text="  < Stop Server", style='Sidebar.TButton', command=self.stop_server_gui, state=tk.DISABLED)
        self.sidebar_stop_button.pack(fill=tk.X, pady=2, padx=5)

        self.sidebar_status_button = ttk.Button(self.sidebar_frame, text="  < Server Status", style='Sidebar.TButton', command=self.show_server_status)
        self.sidebar_status_button.pack(fill=tk.X, pady=2, padx=5)

        ttk.Label(self.sidebar_frame, text="", background=self.bg_dark_primary).pack(pady=10, fill=tk.X) # Separator

        # New Sidebar Buttons: Mode Selection
        self.sidebar_tcp_mode_button = ttk.Button(self.sidebar_frame, text="  < Generic TCP", style='Sidebar.TButton', command=lambda: self.set_server_mode("tcp"))
        self.sidebar_tcp_mode_button.pack(fill=tk.X, pady=2, padx=5)

        self.sidebar_web_http_mode_button = ttk.Button(self.sidebar_frame, text="  < Web Server (HTTP)", style='Sidebar.TButton', command=lambda: self.set_server_mode("web"))
        self.sidebar_web_http_mode_button.pack(fill=tk.X, pady=2, padx=5)

        self.sidebar_web_https_mode_button = ttk.Button(self.sidebar_frame, text="  < Web Server (HTTPS)", style='Sidebar.TButton', command=lambda: self.set_server_mode("https"))
        self.sidebar_web_https_mode_button.pack(fill=tk.X, pady=2, padx=5)

        self.sidebar_ftp_mode_button = ttk.Button(self.sidebar_frame, text="  < FTP Server", style='Sidebar.TButton', command=lambda: self.set_server_mode("ftp"))
        self.sidebar_ftp_mode_button.pack(fill=tk.X, pady=2, padx=5)

        # Bottom sidebar buttons (spacer needed to push to bottom)
        ttk.Label(self.sidebar_frame, text="", background=self.bg_dark_primary).pack(expand=True, fill=tk.BOTH) # Spacer


        # --- Main Content Frame ---
        self.main_content_frame = ttk.Frame(master, style='DarkFrame.TFrame', padding="20 20 20 20")
        self.main_content_frame.grid(row=0, column=1, sticky="nswe")
        self.main_content_frame.grid_rowconfigure(0, weight=0) # Header
        self.main_content_frame.grid_rowconfigure(1, weight=0) # Control inputs
        self.main_content_frame.grid_rowconfigure(2, weight=1) # Log area
        self.main_content_frame.grid_columnconfigure(0, weight=1) # Single column in main content

        # Main content header
        ttk.Label(self.main_content_frame, text="Multi-threaded TCP/Web/FTP Server", style='Header.TLabel', anchor='center').grid(row=0, column=0, pady=15, sticky=tk.N+tk.S+tk.E+tk.W)

        # --- Control Frame (nested within main_content_frame) ---
        self.control_frame = ttk.Frame(self.main_content_frame, padding="15 15 15 15", relief="flat")
        self.control_frame.grid(row=1, column=0, padx=15, pady=15, sticky=tk.N+tk.S+tk.E+tk.W)
        
        # Configure columns for control_frame
        self.control_frame.grid_columnconfigure(0, weight=0) # Labels
        self.control_frame.grid_columnconfigure(1, weight=1) # Inputs
        self.control_frame.grid_columnconfigure(2, weight=0) # Browse buttons

        # Server Port
        self.port_label = ttk.Label(self.control_frame, text="Server Port:")
        self.port_label.grid(row=0, column=0, padx=10, pady=8, sticky=tk.W)
        self.port_entry = ttk.Entry(self.control_frame)
        self.port_entry.insert(0, "9999")
        self.port_entry.grid(row=0, column=1, padx=10, pady=8, sticky=tk.W+tk.E)


        # Web Root Directory Input (initially hidden/disabled)
        self.web_root_label = ttk.Label(self.control_frame, text="Web Root Dir:")
        self.web_root_path_var = tk.StringVar()
        self.web_root_entry = ttk.Entry(self.control_frame, textvariable=self.web_root_path_var)
        self.browse_web_button = ttk.Button(self.control_frame, text="Browse...", command=self.browse_web_root)


        # FTP Root Directory Input (initially hidden/disabled)
        self.ftp_root_label = ttk.Label(self.control_frame, text="FTP Root Dir:")
        self.ftp_root_path_var = tk.StringVar()
        self.ftp_root_entry = ttk.Entry(self.control_frame, textvariable=self.ftp_root_path_var)
        self.browse_ftp_button = ttk.Button(self.control_frame, text="Browse...", command=self.browse_ftp_root)

        # SSL Certificate File Input (new)
        self.ssl_cert_label = ttk.Label(self.control_frame, text="SSL Cert File:")
        self.ssl_cert_path_var = tk.StringVar()
        self.ssl_cert_entry = ttk.Entry(self.control_frame, textvariable=self.ssl_cert_path_var)
        self.browse_ssl_cert_button = ttk.Button(self.control_frame, text="Browse...", command=self.browse_ssl_cert)

        # SSL Key File Input (new)
        self.ssl_key_label = ttk.Label(self.control_frame, text="SSL Key File:")
        self.ssl_key_path_var = tk.StringVar()
        self.ssl_key_entry = ttk.Entry(self.control_frame, textvariable=self.ssl_key_path_var)
        self.browse_ssl_key_button = ttk.Button(self.control_frame, text="Browse...", command=self.browse_ssl_key)


        # --- Log Frame (nested within main_content_frame) ---
        self.log_frame = ttk.Frame(self.main_content_frame, padding="15 15 15 15", relief="flat")
        self.log_frame.grid(row=2, column=0, padx=15, pady=15, sticky=tk.N+tk.S+tk.E+tk.W)
        self.log_frame.grid_rowconfigure(0, weight=1)
        self.log_frame.grid_columnconfigure(0, weight=1)

        # Use the custom scrollbar style
        self.log_text = scrolledtext.ScrolledText(self.log_frame, wrap=tk.WORD, state=tk.DISABLED,
                                                yscrollcommand=lambda *args: self.log_text.tk.call('set', self.log_text_scroll_style, *args))
        # The scrollbar needs to be configured *after* the ScrolledText is created
        # However, scrolledtext implicitly creates its own scrollbar, making direct styling tricky.
        # A common workaround is to create a separate ttk.Scrollbar and associate it.
        # But for 'scrolledtext', we typically apply style to 'TScrollbar' in general,
        # which it then uses for its internal scrollbar. The yscrollcommand lambda is a bit of a hack
        # for specific use cases, but for overall style, configuring TScrollbar directly should work.

        self.log_text.grid(row=0, column=0, sticky=tk.N+tk.S+tk.E+tk.W)


        # Configure log message tags for different colors
        self.log_text.tag_config('info', foreground=self.accent_blue)
        self.log_text.tag_config('success', foreground='#4CAF50') # Green
        self.log_text.tag_config('error', foreground='#ff6b6b')   # Red
        self.log_text.tag_config('warning', foreground='#ffc107') # Yellow

        # Set initial mode and update UI
        self.set_server_mode("tcp") # Default to TCP on startup

        master.protocol("WM_DELETE_WINDOW", self.on_closing)

    def set_server_mode(self, mode):
        """
        Sets the server mode and updates the UI accordingly.

        Args:
            mode (str): The desired server mode ("tcp", "web", "https", "ftp").
        """
        global SERVER_MODE
        if SERVER_RUNNING:
            self.log_message(f"[-] Cannot change server mode while server is running. Stop the server first.", 'warning')
            return

        self.server_mode_var.set(mode)
        SERVER_MODE = mode
        self.log_message(f"[*] Server Mode set to: {mode.upper()}", 'info')
        self.toggle_mode_inputs() # Update root dir visibility
        self.update_sidebar_mode_button_highlight(mode) # Highlight the selected button

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
        global SERVER_RUNNING, SERVER_MODE, server_socket
        status_message = "[*] Server Status: "
        if SERVER_RUNNING:
            try:
                # server_socket.getsockname() can fail if socket is closed/unbound
                server_ip, server_port = server_socket.getsockname()
                status_message += f"RUNNING on {server_ip}:{server_port}\n"
                status_message += f"[*] Current Mode: {SERVER_MODE.upper()}\n"
                if SERVER_MODE == "web" or SERVER_MODE == "https":
                    status_message += f"[*] Web Root: {WEB_ROOT_DIR}\n"
                    if SERVER_MODE == "https":
                        status_message += f"[*] SSL Cert: {SSL_CERT_FILE}\n"
                        status_message += f"[*] SSL Key: {SSL_KEY_FILE}\n"
                elif SERVER_MODE == "ftp":
                    status_message += f"[*] FTP Root: {FTP_ROOT_DIR}\n"
                self.log_message(status_message, 'success')
            except Exception:
                self.log_message(f"[-] Server is running, but socket info unavailable. Check log for errors.", 'warning')
        else:
            status_message += "STOPPED\n"
            self.log_message(status_message, 'error')


    def send_http_response(self, client_socket, status_code, status_message, content, content_type="text/html"):
        """
        Sends an HTTP response to the client.

        Args:
            client_socket (socket.socket or ssl.SSLSocket): The client socket to send the response to.
            status_code (int): The HTTP status code (e.g., 200, 404, 500).
            status_message (str): The HTTP status message (e.g., "OK", "Not Found").
            content (str or bytes): The content of the response body.
            content_type (str, optional): The MIME type of the content. Defaults to "text/html".
        """
        response_line = f"HTTP/1.1 {status_code} {status_message}\r\n"
        headers = f"Content-Type: {content_type}\r\n"
        headers += f"Content-Length: {len(content) if isinstance(content, bytes) else len(content.encode('utf-8'))}\r\n"
        headers += "Connection: close\r\n"
        headers += "\r\n"

        if isinstance(content, str):
            content_bytes = content.encode('utf-8')
        else:
            content_bytes = content

        response = response_line.encode('utf-8') + headers.encode('utf-8') + content_bytes
        try:
            client_socket.sendall(response)
        except Exception as e:
            self.log_message(f"[-] Error sending HTTP response: {e}", 'error')

    def toggle_mode_inputs(self):
        """
        Shows or hides the web/ftp root directory and SSL inputs based on the selected server mode.
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
            self.web_root_label.grid(row=1, column=0, padx=10, pady=8, sticky=tk.W)
            self.web_root_entry.grid(row=1, column=1, padx=10, pady=8, sticky=tk.W+tk.E)
            self.browse_web_button.grid(row=1, column=2, padx=10, pady=8, sticky=tk.W)
        elif current_mode == "https":
            self.web_root_label.grid(row=1, column=0, padx=10, pady=8, sticky=tk.W)
            self.web_root_entry.grid(row=1, column=1, padx=10, pady=8, sticky=tk.W+tk.E)
            self.browse_web_button.grid(row=1, column=2, padx=10, pady=8, sticky=tk.W)
            
            self.ssl_cert_label.grid(row=2, column=0, padx=10, pady=8, sticky=tk.W)
            self.ssl_cert_entry.grid(row=2, column=1, padx=10, pady=8, sticky=tk.W+tk.E)
            self.browse_ssl_cert_button.grid(row=2, column=2, padx=10, pady=8, sticky=tk.W)

            self.ssl_key_label.grid(row=3, column=0, padx=10, pady=8, sticky=tk.W)
            self.ssl_key_entry.grid(row=3, column=1, padx=10, pady=8, sticky=tk.W+tk.E)
            self.browse_ssl_key_button.grid(row=3, column=2, padx=10, pady=8, sticky=tk.W)

        elif current_mode == "ftp":
            self.ftp_root_label.grid(row=1, column=0, padx=10, pady=8, sticky=tk.W)
            self.ftp_root_entry.grid(row=1, column=1, padx=10, pady=8, sticky=tk.W+tk.E)
            self.browse_ftp_button.grid(row=1, column=2, padx=10, pady=8, sticky=tk.W)

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
        filepath = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if filepath:
            self.ssl_cert_path_var.set(filepath)

    def browse_ssl_key(self):
        """Opens a file selection dialog for the SSL key file."""
        filepath = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if filepath:
            self.ssl_key_path_var.set(filepath)

    def log_message(self, message, tag=None):
        """
        Appends a message to the log text area in a thread-safe manner with optional tag for coloring.

        Args:
            message (str): The message to log.
            tag (str, optional): A tag for coloring the message (e.g., 'info', 'success', 'error', 'warning'). Defaults to None.
        """
        self.master.after(0, self._append_log, message, tag)

    def _append_log(self, message, tag):
        """
        Internal method to append message to log_text.
        This method is called via `master.after` to ensure it runs on the main Tkinter thread.

        Args:
            message (str): The message to append.
            tag (str): The tag for coloring.
        """
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n", tag)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def handle_client(self, client_socket, client_address):
        """
        Handles an individual client connection based on SERVER_MODE.

        Args:
            client_socket (socket.socket or ssl.SSLSocket): The socket object for the client connection.
            client_address (tuple): A tuple containing the client's IP address and port.
        """
        global SERVER_MODE, WEB_ROOT_DIR, FTP_ROOT_DIR

        client_socket.settimeout(1.0) # Set a timeout for client sockets

        if SERVER_MODE == "tcp":
            try:
                request = client_socket.recv(1024)
                if not request:
                    self.log_message(f"[*] Client {client_address[0]}:{client_address[1]} disconnected.", 'info')
                    return
                self.log_message(f"[*] Received from {client_address[0]}:{client_address[1]}: {request.decode('utf-8', errors='ignore')}", 'info')
                client_socket.sendall(b"ACK!")
            except ConnectionResetError:
                self.log_message(f"[-] Client {client_address[0]}:{client_address[1]} reset the connection.", 'warning')
            except socket.timeout:
                self.log_message(f"[*] Client {client_address[0]}:{client_address[1]} timed out (TCP).", 'info')
            except Exception as e:
                self.log_message(f"[-] Error handling client {client_address[0]}:{client_address[1]}: {e}", 'error')
            finally:
                client_socket.close()

        elif SERVER_MODE == "web" or SERVER_MODE == "https":
            try:
                request_data = client_socket.recv(4096).decode('utf-8', errors='ignore')
                if not request_data:
                    self.log_message(f"[*] Web Client {client_address[0]}:{client_address[1]} disconnected.", 'info')
                    return

                first_line = request_data.split('\n')[0]
                self.log_message(f"[*] Web Request from {client_address[0]}:{client_address[1]}: {first_line}", 'info')

                parts = first_line.split(' ')
                if len(parts) < 2:
                    self.send_http_response(client_socket, 400, "Bad Request", "<h1>400 Bad Request</h1>")
                    self.log_message(f"[-] Bad Web Request from {client_address[0]}:{client_address[1]}", 'warning')
                    return

                method = parts[0]
                path = parts[1]

                if method != 'GET':
                    self.send_http_response(client_socket, 405, "Method Not Allowed", "<h1>405 Method Not Allowed</h1>")
                    self.log_message(f"[-] Method Not Allowed: {method} from {client_address[0]}:{client_address[1]}", 'warning')
                    return

                clean_path = os.path.normpath(path).replace('\\', '/')
                if clean_path.startswith('/'):
                    clean_path = clean_path[1:]

                if not clean_path or clean_path.endswith('/'):
                    clean_path = os.path.join(clean_path, 'index.html')

                file_path = os.path.join(WEB_ROOT_DIR, clean_path)

                abs_file_path = os.path.abspath(file_path)
                abs_web_root_dir = os.path.abspath(WEB_ROOT_DIR)

                if not abs_file_path.startswith(abs_web_root_dir):
                    self.log_message(f"[-] Attempted directory traversal: {file_path} from {client_address[0]}:{client_address[1]}", 'error')
                    self.send_http_response(client_socket, 403, "Forbidden", "<h1>403 Forbidden</h1>")
                    return

                if os.path.exists(file_path) and os.path.isfile(file_path):
                    mimetype, _ = mimetypes.guess_type(file_path)
                    if not mimetype:
                        mimetype = 'application/octet-stream'

                    with open(file_path, 'rb') as f:
                        content = f.read()

                    self.send_http_response(client_socket, 200, "OK", content, mimetype)
                    self.log_message(f"[+] Served: {file_path} (Type: {mimetype}) to {client_address[0]}:{client_address[1]}", 'success')
                else:
                    self.send_http_response(client_socket, 404, "Not Found", "<h1>404 Not Found</h1>")
                    self.log_message(f"[-] File not found: {file_path} for {client_address[0]}:{client_address[1]}", 'warning')
            except socket.timeout:
                self.log_message(f"[*] Web Client {client_address[0]}:{client_address[1]} timed out (Web).", 'info')
            except ssl.SSLError as e:
                # This can happen if a non-HTTPS client tries to connect to an HTTPS server
                self.log_message(f"[-] SSL Error with client {client_address[0]}:{client_address[1]}: {e}", 'warning')
            except Exception as e:
                self.log_message(f"[-] Error handling web client {client_address[0]}:{client_address[1]}: {e}", 'error')
                self.send_http_response(client_socket, 500, "Internal Server Error", "<h1>500 Internal Server Error</h1>")
            finally:
                client_socket.close()

        elif SERVER_MODE == "ftp":
            authenticated = False
            ftp_username_attempt = None
            current_ftp_dir = FTP_ROOT_DIR
            data_socket = None
            pasv_listener = None

            def ftp_send_response(sock, code, message):
                """
                Sends an FTP response to the client.

                Args:
                    sock (socket.socket): The client control socket.
                    code (int): The FTP response code.
                    message (str): The FTP response message.
                """
                response = f"{code} {message}\r\n"
                try:
                    sock.sendall(response.encode('utf-8'))
                    self.log_message(f"[FTP] Sent {code}: {message}", 'info')
                except Exception as e:
                    self.log_message(f"[-] FTP Send Error: {e}", 'error')

            def ftp_open_data_connection(data_addr, data_port):
                """
                Attempts to establish an active mode FTP data connection.

                Args:
                    data_addr (str): The IP address for the data connection.
                    data_port (int): The port for the data connection.

                Returns:
                    bool: True if connection is successful, False otherwise.
                """
                nonlocal data_socket
                try:
                    data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    data_socket.settimeout(10)
                    data_socket.connect((data_addr, data_port))
                    self.log_message(f"[FTP] Active data connection established to {data_addr}:{data_port}", 'info')
                    return True
                except Exception as e:
                    self.log_message(f"[-] FTP Active Data Connect Error: {e}", 'error')
                    data_socket = None
                    return False

            def ftp_start_pasv_listener():
                """
                Starts a passive mode FTP data listener.

                Returns:
                    tuple: (address, port) if successful, (None, None) otherwise.
                """
                nonlocal pasv_listener
                try:
                    pasv_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    pasv_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    pasv_listener.bind(('0.0.0.0', 0))
                    pasv_listener.listen(1)
                    addr, port = pasv_listener.getsockname()
                    self.log_message(f"[FTP] Passive listener started on {addr}:{port}", 'info')
                    return addr, port
                except Exception as e:
                    self.log_message(f"[-] FTP Passive Listener Error: {e}", 'error')
                    if pasv_listener:
                        pasv_listener.close()
                    pasv_listener = None
                    return None, None

            def ftp_accept_pasv_connection():
                """
                Accepts a passive mode FTP data connection.

                Returns:
                    bool: True if connection is accepted, False otherwise.
                """
                nonlocal data_socket, pasv_listener
                if not pasv_listener:
                    return False
                try:
                    data_socket, _ = pasv_listener.accept()
                    data_socket.settimeout(10)
                    self.log_message("[FTP] Passive data connection accepted.", 'info')
                    return True
                except socket.timeout:
                    self.log_message("[-] FTP Passive Data Accept Timeout.", 'warning')
                    data_socket = None
                    return False
                except Exception as e:
                    self.log_message(f"[-] FTP Passive Data Accept Error: {e}", 'error')
                    data_socket = None
                    return False
                finally:
                    if pasv_listener:
                        pasv_listener.close()
                        pasv_listener = None

            ftp_send_response(client_socket, 220, "Welcome to the Python FTP Server.")

            try:
                while SERVER_RUNNING:
                    try:
                        client_socket.settimeout(0.5)
                        command_line = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
                    except socket.timeout:
                        continue
                    except Exception as e:
                        self.log_message(f"[-] FTP Client Recv Error {client_address[0]}:{client_address[1]}: {e}", 'error')
                        break

                    if not command_line:
                        self.log_message(f"[*] FTP Client {client_address[0]}:{client_address[1]} disconnected.", 'info')
                        break

                    self.log_message(f"[FTP] Received from {client_address[0]}:{client_address[1]}: {command_line}", 'info')

                    parts = command_line.split(' ', 1)
                    cmd = parts[0].upper()
                    arg = parts[1] if len(parts) > 1 else ""

                    if cmd == "USER":
                        if arg == "ftpuser":
                            ftp_send_response(client_socket, 331, "Password required for ftpuser.")
                            ftp_username_attempt = arg
                        else:
                            ftp_username_attempt = None
                            ftp_send_response(client_socket, 530, "Not logged in, username incorrect.")
                    elif cmd == "PASS":
                        if ftp_username_attempt == "ftpuser" and arg == "ftppass":
                            authenticated = True
                            ftp_send_response(client_socket, 230, "User logged in, proceed.")
                            current_ftp_dir = os.path.abspath(FTP_ROOT_DIR)
                            self.log_message(f"[FTP] Client {client_address[0]}:{client_address[1]} authenticated. Root: {current_ftp_dir}", 'success')
                        else:
                            authenticated = False
                            ftp_send_response(client_socket, 530, "Not logged in, password incorrect.")
                    elif cmd == "QUIT":
                        ftp_send_response(client_socket, 221, "Goodbye.")
                        break

                    elif not authenticated:
                        ftp_send_response(client_socket, 530, "Not logged in.")

                    elif cmd == "SYST":
                        ftp_send_response(client_socket, 215, "UNIX Type: L8")
                    elif cmd == "FEAT":
                        ftp_send_response(client_socket, 211, "Extensions supported:\r\n PASV\r\n QUIT")
                        ftp_send_response(client_socket, 211, "End")
                    elif cmd == "PWD":
                        display_path = os.path.relpath(current_ftp_dir, FTP_ROOT_DIR).replace('\\', '/')
                        if display_path == '.':
                            display_path = '/'
                        elif not display_path.startswith('/'):
                            display_path = '/' + display_path
                        ftp_send_response(client_socket, 257, f'"{display_path}" is current directory.')
                    elif cmd == "CWD":
                        requested_path = os.path.normpath(os.path.join(current_ftp_dir, arg))
                        abs_requested_path = os.path.abspath(requested_path)
                        abs_ftp_root_dir = os.path.abspath(FTP_ROOT_DIR)

                        if not abs_requested_path.startswith(abs_ftp_root_dir):
                            ftp_send_response(client_socket, 550, "Permission denied. Cannot go outside root directory.")
                        elif os.path.isdir(abs_requested_path):
                            current_ftp_dir = abs_requested_path
                            ftp_send_response(client_socket, 250, "Directory successfully changed.")
                        else:
                            ftp_send_response(client_socket, 550, "Failed to change directory. Directory not found.")

                    elif cmd == "PORT":
                        try:
                            parts = [int(x) for x in arg.split(',')]
                            data_addr = ".".join(map(str, parts[0:4]))
                            data_port = parts[4] * 256 + parts[5]

                            try:
                                ipaddress.ip_address(data_addr)
                            except ValueError:
                                ftp_send_response(client_socket, 501, "Syntax error in parameters or arguments.")
                                continue

                            if ftp_open_data_connection(data_addr, data_port):
                                ftp_send_response(client_socket, 200, "PORT command successful. Consider using PASV.")
                            else:
                                ftp_send_response(client_socket, 425, "Can't open data connection.")
                        except Exception:
                            ftp_send_response(client_socket, 501, "Syntax error in parameters or arguments.")
                    elif cmd == "PASV":
                        addr, port = ftp_start_pasv_listener()
                        if addr and port:
                            ip_parts = addr.split('.')
                            p1 = port // 256
                            p2 = port % 256
                            ftp_send_response(client_socket, 227, f"Entering Passive Mode ({ip_parts[0]},{ip_parts[1]},{ip_parts[2]},{ip_parts[3]},{p1},{p2}).")
                        else:
                            ftp_send_response(client_socket, 421, "Service not available, closing control connection.")
                            break

                    elif cmd == "LIST":
                        if data_socket:
                            ftp_send_response(client_socket, 150, "Opening ASCII mode data connection for file list.")
                            try:
                                files = os.listdir(current_ftp_dir)
                                list_output = ""
                                for item in files:
                                    full_path = os.path.join(current_ftp_dir, item)
                                    if os.path.isdir(full_path):
                                        list_output += f"drwxr-xr-x 1 ftp ftp 0 Jan 01 00:00 {item}\r\n"
                                    else:
                                        size = os.path.getsize(full_path)
                                        list_output += f"-rw-r--r-- 1 ftp ftp {size} Jan 01 00:00 {item}\r\n"
                                data_socket.sendall(list_output.encode('utf-8'))
                                ftp_send_response(client_socket, 226, "Transfer complete.")
                            except Exception as e:
                                ftp_send_response(client_socket, 550, f"Failed to list directory: {e}")
                            finally:
                                if data_socket:
                                    data_socket.close()
                                    data_socket = None
                        elif pasv_listener:
                            ftp_send_response(client_socket, 150, "Opening ASCII mode data connection for file list.")
                            if ftp_accept_pasv_connection():
                                try:
                                    files = os.listdir(current_ftp_dir)
                                    list_output = ""
                                    for item in files:
                                        full_path = os.path.join(current_ftp_dir, item)
                                        if os.path.isdir(full_path):
                                            list_output += f"drwxr-xr-x 1 ftp ftp 0 Jan 01 00:00 {item}\r\n"
                                        else:
                                            size = os.path.getsize(full_path)
                                            list_output += f"-rw-r--r-- 1 ftp ftp {size} Jan 01 00:00 {item}\r\n"
                                    data_socket.sendall(list_output.encode('utf-8'))
                                    ftp_send_response(client_socket, 226, "Transfer complete.")
                                except Exception as e:
                                    ftp_send_response(client_socket, 550, f"Failed to list directory: {e}")
                                finally:
                                    if data_socket:
                                        data_socket.close()
                                        data_socket = None
                            else:
                                ftp_send_response(client_socket, 425, "Can't open data connection.")
                        else:
                            ftp_send_response(client_socket, 425, "Use PORT or PASV first.")

                    elif cmd == "RETR":
                        file_to_retrieve = os.path.join(current_ftp_dir, arg)
                        abs_file_path = os.path.abspath(file_to_retrieve)
                        abs_ftp_root_dir = os.path.abspath(FTP_ROOT_DIR)

                        if not abs_file_path.startswith(abs_ftp_root_dir):
                            ftp_send_response(client_socket, 550, "Permission denied. Cannot retrieve file outside root.")
                        elif not os.path.exists(file_to_retrieve) or not os.path.isfile(file_to_retrieve):
                            ftp_send_response(client_socket, 550, "File not found.")
                        elif data_socket:
                            ftp_send_response(client_socket, 150, f"Opening BINARY mode data connection for {arg}.")
                            try:
                                with open(file_to_retrieve, 'rb') as f:
                                    while True:
                                        chunk = f.read(4096)
                                        if not chunk:
                                            break
                                        data_socket.sendall(chunk)
                                ftp_send_response(client_socket, 226, "Transfer complete.")
                            except Exception as e:
                                ftp_send_response(client_socket, 550, f"Failed to retrieve file: {e}")
                            finally:
                                if data_socket:
                                    data_socket.close()
                                    data_socket = None
                        elif pasv_listener:
                            ftp_send_response(client_socket, 150, f"Opening BINARY mode data connection for {arg}.")
                            if ftp_accept_pasv_connection():
                                try:
                                    with open(file_to_retrieve, 'rb') as f:
                                        while True:
                                            chunk = f.read(4096) # Read from file
                                            if not chunk:
                                                break
                                            data_socket.sendall(chunk) # Send to client
                                    ftp_send_response(client_socket, 226, "Transfer complete.")
                                except Exception as e:
                                    ftp_send_response(client_socket, 550, f"Failed to retrieve file: {e}")
                                finally:
                                    if data_socket:
                                        data_socket.close()
                                        data_socket = None
                            else:
                                ftp_send_response(client_socket, 425, "Can't open data connection.")
                        else:
                            ftp_send_response(client_socket, 425, "Use PORT or PASV first.")

                    elif cmd == "STOR":
                        file_to_store = os.path.join(current_ftp_dir, arg)
                        abs_file_path = os.path.abspath(file_to_store)
                        abs_ftp_root_dir = os.path.abspath(FTP_ROOT_DIR)

                        if not abs_file_path.startswith(abs_ftp_root_dir):
                            ftp_send_response(client_socket, 550, "Permission denied. Cannot store file outside root.")
                        elif data_socket:
                            ftp_send_response(client_socket, 150, f"Opening BINARY mode data connection for {arg}.")
                            try:
                                with open(file_to_store, 'wb') as f:
                                    while True:
                                        chunk = data_socket.recv(4096) # Receive from client
                                        if not chunk:
                                            break
                                        f.write(chunk)
                                ftp_send_response(client_socket, 226, "Transfer complete.")
                            except Exception as e:
                                ftp_send_response(client_socket, 550, f"Failed to store file: {e}")
                            finally:
                                if data_socket:
                                    data_socket.close()
                                    data_socket = None
                        elif pasv_listener:
                            ftp_send_response(client_socket, 150, f"Opening BINARY mode data connection for {arg}.")
                            if ftp_accept_pasv_connection():
                                try:
                                    with open(file_to_store, 'wb') as f:
                                        while True:
                                            chunk = data_socket.recv(4096)
                                            if not chunk:
                                                break
                                            f.write(chunk)
                                    ftp_send_response(client_socket, 226, "Transfer complete.")
                                except Exception as e:
                                    ftp_send_response(client_socket, 550, f"Failed to store file: {e}")
                                finally:
                                    if data_socket:
                                        data_socket.close()
                                        data_socket = None
                            else:
                                ftp_send_response(client_socket, 425, "Can't open data connection.")
                        else:
                            ftp_send_response(client_socket, 425, "Use PORT or PASV first.")

                    else:
                        ftp_send_response(client_socket, 502, "Command not implemented.")

            except Exception as e:
                self.log_message(f"[-] FTP Client Error {client_address[0]}:{client_address[1]}: {e}", 'error')
            finally:
                if data_socket:
                    data_socket.close()
                if pasv_listener:
                    pasv_listener.close()
                client_socket.close()

    def _server_main_loop(self, port):
        """
        The main loop for the server, run in a separate thread.
        Listens for incoming connections and spawns client handlers.

        Args:
            port (int): The port number to bind the server to.
        """
        global SERVER_RUNNING, server_socket, SERVER_MODE, WEB_ROOT_DIR, FTP_ROOT_DIR, SSL_CERT_FILE, SSL_KEY_FILE

        # Get values from GUI inputs
        WEB_ROOT_DIR = self.web_root_path_var.get()
        FTP_ROOT_DIR = self.ftp_root_path_var.get()
        SSL_CERT_FILE = self.ssl_cert_path_var.get()
        SSL_KEY_FILE = self.ssl_key_path_var.get()


        if SERVER_MODE == "web" or SERVER_MODE == "https":
            if not WEB_ROOT_DIR or not os.path.isdir(WEB_ROOT_DIR):
                self.log_message("[-] Web Server mode selected, but Web Root Directory is invalid or not set.", 'error')
                self.log_message("[-] Please select a valid directory for web hosting.", 'error')
                SERVER_RUNNING = False
                self.master.after(0, self.update_button_states)
                return
            self.log_message(f"[*] Web Server Mode ({SERVER_MODE.upper()}): Serving files from: {WEB_ROOT_DIR}", 'info')
        
        if SERVER_MODE == "https":
            if not SSL_CERT_FILE or not os.path.isfile(SSL_CERT_FILE):
                self.log_message("[-] HTTPS mode selected, but SSL Certificate file is invalid or not set.", 'error')
                self.log_message("[-] Please select a valid .pem certificate file.", 'error')
                SERVER_RUNNING = False
                self.master.after(0, self.update_button_states)
                return
            if not SSL_KEY_FILE or not os.path.isfile(SSL_KEY_FILE):
                self.log_message("[-] HTTPS mode selected, but SSL Key file is invalid or not set.", 'error')
                self.log_message("[-] Please select a valid .pem key file.", 'error')
                SERVER_RUNNING = False
                self.master.after(0, self.update_button_states)
                return
            self.log_message(f"[*] HTTPS Mode: Using Certificate: {SSL_CERT_FILE}", 'info')
            self.log_message(f"[*] HTTPS Mode: Using Key: {SSL_KEY_FILE}", 'info')


        elif SERVER_MODE == "ftp":
            if not FTP_ROOT_DIR or not os.path.isdir(FTP_ROOT_DIR):
                self.log_message("[-] FTP Server mode selected, but FTP Root Directory is invalid or not set.", 'error')
                self.log_message("[-] Please select a valid directory for FTP hosting.", 'error')
                SERVER_RUNNING = False
                self.master.after(0, self.update_button_states)
                return
            self.log_message(f"[*] FTP Server Mode: Serving files from: {FTP_ROOT_DIR}", 'info')
            self.log_message("[*] FTP Login: User 'ftpuser', Pass 'ftppass'", 'info')

        bind_ip = "0.0.0.0"

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_socket.bind((bind_ip, port))
        except socket.error as e:
            self.log_message(f"[-] Could not bind to port {port}: {e}", 'error')
            self.log_message("[-] Please check if the port is already in use or if you have sufficient permissions.", 'error')
            SERVER_RUNNING = False
            self.master.after(0, self.update_button_states)
            return

        server_socket.listen(5)
        self.log_message(f"[*] Listening on {bind_ip}:{port}", 'info')

        # Wrap socket with SSL if in HTTPS mode
        if SERVER_MODE == "https":
            try:
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                # For a self-signed certificate, you might not need CLIENT_AUTH.
                # ssl.Purpose.SERVER_AUTH is typically for clients verifying servers.
                # However, for server-side, load_cert_chain handles the server's identity.
                context.load_cert_chain(certfile=SSL_CERT_FILE, keyfile=SSL_KEY_FILE)
                server_socket = context.wrap_socket(server_socket, server_side=True)
                self.log_message("[*] Server socket wrapped with SSL/TLS.", 'success')
            except ssl.SSLError as e:
                self.log_message(f"[-] SSL Error wrapping socket: {e}", 'error')
                self.log_message("[-] Please check your SSL certificate and key files.", 'error')
                SERVER_RUNNING = False
                server_socket.close()
                self.master.after(0, self.update_button_states)
                return
            except FileNotFoundError as e:
                self.log_message(f"[-] SSL Certificate or Key file not found: {e}", 'error')
                SERVER_RUNNING = False
                server_socket.close()
                self.master.after(0, self.update_button_states)
                return
            except Exception as e:
                self.log_message(f"[-] General error during SSL setup: {e}", 'error')
                SERVER_RUNNING = False
                server_socket.close()
                self.master.after(0, self.update_button_states)
                return

        SERVER_RUNNING = True
        self.master.after(0, self.update_button_states)
        server_socket.settimeout(1.0) # Timeout for accept to allow graceful shutdown

        while SERVER_RUNNING:
            try:
                # For HTTPS, client will already be an SSLSocket after accept
                client, addr = server_socket.accept()
                self.log_message(f"[*] Accepted connection from: {addr[0]}:{addr[1]} (Mode: {SERVER_MODE})", 'info')

                client_handler = threading.Thread(target=self.handle_client, args=(client, addr))
                client_handler.daemon = True
                client_handler.start()
            except socket.timeout:
                continue
            except Exception as e:
                if SERVER_RUNNING: # Only log if server was intended to be running
                    self.log_message(f"[-] Error accepting connection: {e}", 'error')
                break

        self.log_message("[*] Server main loop exited.", 'info')
        self.master.after(0, self.update_button_states)

    def start_server_gui(self):
        """
        Initiates the server startup process based on GUI input.
        Performs input validation and starts the server in a new thread.
        """
        global SERVER_RUNNING
        if SERVER_RUNNING:
            self.log_message("[*] Server is already running.", 'warning')
            return

        try:
            port = int(self.port_entry.get())
            if not (1 <= port <= 65535):
                messagebox.showerror("Invalid Port", "Port number must be between 1 and 65535.")
                return
        except ValueError:
            messagebox.showerror("Invalid Port", "Please enter a valid integer for the port.")
            return

        current_mode = self.server_mode_var.get()
        if current_mode == "web" or current_mode == "https":
            web_root = self.web_root_path_var.get()
            if not web_root or not os.path.isdir(web_root):
                messagebox.showerror("Invalid Web Root", "Please select a valid web root directory for Web Server mode.")
                return
            if current_mode == "https":
                ssl_cert = self.ssl_cert_path_var.get()
                ssl_key = self.ssl_key_path_var.get()
                if not ssl_cert or not os.path.isfile(ssl_cert):
                    messagebox.showerror("Invalid SSL Certificate", "Please select a valid SSL certificate file (.pem) for HTTPS mode.")
                    return
                if not ssl_key or not os.path.isfile(ssl_key):
                    messagebox.showerror("Invalid SSL Key", "Please select a valid SSL key file (.pem) for HTTPS mode.")
                    return

        elif current_mode == "ftp":
            ftp_root = self.ftp_root_path_var.get()
            if not ftp_root or not os.path.isdir(ftp_root):
                messagebox.showerror("Invalid FTP Root", "Please select a valid FTP root directory for FTP Server mode.")
                return

        self.log_message(f"[*] Attempting to start server on port {port} in {current_mode.upper()} mode...", 'info')

        self.server_thread = threading.Thread(target=self._server_main_loop, args=(port,))
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop_server_gui(self):
        """
        Initiates the server shutdown process.
        Sets a global flag to stop the server's main loop and closes the server socket.
        """
        global SERVER_RUNNING, server_socket
        if not SERVER_RUNNING:
            self.log_message("[*] Server is not running.", 'warning')
            return

        self.log_message("[*] Stopping server...", 'info')
        SERVER_RUNNING = False

        time.sleep(0.1)

        if server_socket:
            try:
                server_socket.shutdown(socket.SHUT_RDWR)
                server_socket.close()
                self.log_message("[*] Server socket closed.", 'info')
            except Exception as e:
                self.log_message(f"[-] Error closing server socket: {e}", 'error')

        self.log_message("[*] Server stop signal sent. Waiting for thread to terminate...", 'info')

    def update_button_states(self, starting=False):
        """
        Updates the state of the Start/Stop buttons (now in sidebar) and input fields based on server status.

        Args:
            starting (bool, optional): True if the server is in the process of starting. Defaults to False.
        """
        global SERVER_RUNNING
        
        mode_buttons = [
            self.sidebar_tcp_mode_button,
            self.sidebar_web_http_mode_button,
            self.sidebar_web_https_mode_button,
            self.sidebar_ftp_mode_button
        ]

        if SERVER_RUNNING:
            self.sidebar_start_button.config(state=tk.DISABLED)
            self.sidebar_stop_button.config(state=tk.NORMAL)
            self.sidebar_status_button.config(state=tk.NORMAL) # Enable status when running

            self.port_entry.config(state=tk.DISABLED)
            
            # Disable mode selection buttons when server is running
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
            self.sidebar_status_button.config(state=tk.NORMAL) # Status always visible

            self.port_entry.config(state=tk.NORMAL)
            
            # Enable mode selection buttons when server is stopped
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
            else: # TCP mode
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
        Prompts the user to confirm quitting and stops the server if it's running.
        """
        if messagebox.askokcancel("Quit", "Do you want to quit NetWeaver?"):
            self.stop_server_gui()
            time.sleep(0.5)
            self.master.destroy()

if __name__ == "__main__":
    # Ignore SIGINT (Ctrl+C) to prevent the main thread from being interrupted
    # while child threads might still be active, allowing for a cleaner shutdown via GUI.
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    root = tk.Tk()
    app = TCPServerGUI(root)
    root.mainloop()