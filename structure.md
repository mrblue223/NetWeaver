Netweaver/
├── assets/
│   └── icons8-server-40.png  (GUI icon, download if not present)
├── main.py                   (Main entry point for the GUI application)
├── gui.py                    (Contains the Tkinter GUI class: TCPServerGUI)
├── constants.py              (Stores global variables, theme settings, and common configurations)
├── server_core.py            (Core server logic: main loop, socket binding, connection dispatching)
├── tcp_handler.py            (Handles generic TCP client connections)
├── web_handler.py            (Handles HTTP/HTTPS web client requests)
└── ftp_handler.py            (Handles FTP client commands and data transfers)
