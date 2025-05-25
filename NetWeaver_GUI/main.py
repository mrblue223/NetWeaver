import tkinter as tk
import signal
import time
from gui import TCPServerGUI
from constants import SERVER_RUNNING, SERVER_SOCKET, SERVER_MODE

if __name__ == "__main__":
    # Ignore SIGINT (Ctrl+C) to prevent the main thread from being interrupted
    # while child threads might still be active, allowing for a cleaner
    # shutdown via GUI.
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    root = tk.Tk()
    app = TCPServerGUI(root)
    root.mainloop()

    # Ensure server is stopped if GUI is closed directly
    if SERVER_RUNNING:
        print("[*] GUI closed, attempting to stop server...")
        SERVER_RUNNING = False
        if SERVER_SOCKET:
            try:
                SERVER_SOCKET.shutdown(socket.SHUT_RDWR)
                SERVER_SOCKET.close()
                print("[*] Server socket closed.")
            except Exception as e:
                print(f"[-] Error closing server socket during shutdown: {e}")
        time.sleep(0.5) # Give a moment for threads to acknowledge stop