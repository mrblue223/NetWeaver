The GUI
![Alt text for the image](Netweaver_2/assets/NetWeaver.png)

## Table of contents

- [Introduction](#Introduction)
- [Prerequisites](#Prerequisites)
- [Project-Structure](#Project-Structure)
- [Running-the-Application](#Running-the-Application)
    - [Server-Modes](#Server-Modes)
        - [Web-Server(HTTP)](#Web-Server(HTTP))
        - [Web-Server(HTTPS)](#Web-Server(HTTPS))
        - [FTP-Server](#FTP-Server)
    - [Log-Area](#Log-Area)
- [Troubleshooting](#Troubleshooting)
- [Contributing](#Contributing)
- [License](#License)

## NetWeaver - Multi-threaded TCP/Web/FTP Server

A versatile, multi-threaded server application with a graphical user interface, supporting generic TCP, HTTP/HTTPS, and FTP protocols.
Table of Contents


## Introduction

NetWeaver is a Python-based server application designed to provide flexible network services through a user-friendly graphical interface. It supports handling multiple client connections concurrently across different protocols, including a generic TCP server, a web server (HTTP and HTTPS), and an FTP server. The application aims to offer a simple yet powerful tool for testing network communications and serving files.
Features

    Multi-threaded Architecture: Handles multiple client connections simultaneously without blocking the main application thread.

    Multiple Server Modes:

        Generic TCP Server: For basic TCP communication and testing.

        Web Server (HTTP): Serves static files from a specified root directory.

        Web Server (HTTPS): Provides secure web serving using SSL/TLS with user-provided certificate and key files.

        FTP Server: Supports basic FTP commands for file listing, retrieval, and storage, with user authentication.

    Intuitive Graphical User Interface (GUI): Built with Tkinter, featuring a modern dark theme for easy configuration and real-time logging.

    Real-time Logging: Displays server activity, client connections, requests, and errors directly within the GUI.

    File System Security: Implements checks to prevent directory traversal attacks for both web and FTP serving.

    Configurable Root Directories: Allows users to specify separate root directories for web and FTP content.

    SSL/TLS Support: Enables secure communication for the HTTPS server mode.

    Basic FTP Commands: Supports USER, PASS, PWD, CWD, LIST, RETR, STOR, PORT, and PASV commands.

## Prerequisites

To run NetWeaver, you need the following:

    Python 3: The application is developed in Python 3.

    run the install_depencies.py script

## Setup and Installation

    Clone the repository (or download the files):

    git clone https://github.com/mrblue223/NetWeaver.git
    cd Netweaver

    Install dependencies:
    python3 install_dependencies.py

    Ensure the assets directory exists:
    Make sure the assets/icons8-server-40.png file is present in the Netweaver/assets/ directory for the GUI icon to display correctly. If not, you can download it or provide your own icon.

## Project-Structure


## File Breakdown

### `Netweaver/` (Root Directory)
This is the top-level directory containing all project files.

### `assets/`
Contains static assets used by the application, such as icons.
* `icons8-server-40.png`: The icon used for the GUI application. This image should be downloaded and placed here if not already present.

### `main.py`
This is the primary entry point for the entire application.
* Initializes the Tkinter GUI.
* Starts the server logic.
* Coordinates between the GUI and the server backend.

### `gui.py`
Defines the graphical user interface components using Tkinter.
* Contains the `TCPServerGUI` class, responsible for rendering the server's status, logs, and controls.
* Handles user interactions with the GUI.

### `constants.py`
A centralized location for application-wide constants and configurations.
* Stores global variables, such as default port numbers, buffer sizes, and server addresses.
* Defines theme settings (e.g., colors, fonts) for the GUI.
* Any other common configurations shared across modules.

### `server_core.py`
Encapsulates the fundamental server operations.
* Manages the main server loop.
* Handles socket binding and listening for incoming connections.
* Dispatches incoming connections to appropriate handler modules (e.g., `tcp_handler`, `web_handler`, `ftp_handler`).

### `tcp_handler.py`
Provides generic handling for raw TCP client connections.
* Manages the lifecycle of a standard TCP connection.
* Implements basic send and receive operations for raw TCP data.
* Could be extended for custom TCP-based protocols.

### `web_handler.py`
Specialized handler for HTTP/HTTPS web client requests.
* Parses incoming HTTP/HTTPS requests.
* Routes requests to appropriate internal functions based on URL paths and methods.
* Generates HTTP/HTTPS responses.

### `ftp_handler.py`
Manages FTP (File Transfer Protocol) client commands and data transfers.
* Handles FTP control connections (commands like `USER`, `PASS`, `LIST`, `RETR`, `STOR`).
* Manends FTP data connections for actual file transfers.
* Ensures proper FTP protocol adherence.

---

## How to use this `structure.md` file:

1.  **Create the file:** In the root of your `Netweaver` project directory, create a new file named `structure.md`.
2.  **Copy the content:** Paste the Markdown content provided above into your `structure.md` file.
3.  **Commit and Push:** Add the `structure.md` file to your Git repository, commit it, and push it to GitHub.

When you navigate to the `structure.md` file on your GitHub repository, it will automatically render the Markdown, displaying your project structure clearly.

**Key GFM considerations applied:**
* **Code Block for Tree:** The directory tree itself is enclosed in a Markdown code block (```) to preserve its formatting and indentation.
* **Headings:** `#` and `##` are used for clear section headings.
* **Lists:** Bullet points (`*`) are used for file breakdowns for readability.
* **Emphasis:** Code snippets like filenames are enclosed in backticks (`` `filename.py` ``) for inline code highlighting.


## Running-the-Application

To start the NetWeaver server GUI, navigate to the Netweaver directory and run the main.py script:

python main.py

Using the GUI

Once the GUI launches, you can configure and control the server using its intuitive interface.
Server Controls

    Start Server: Initiates the server on the specified port and mode.

    Stop Server: Shuts down the running server.

    Server Status: Displays the current status of the server (running/stopped), including its IP, port, mode, and configured root directories/SSL files.

## Server Modes

You can select the desired server mode from the sidebar. The input fields in the main content area will dynamically adjust based on your selection.
Generic TCP Server

    Purpose: For basic TCP communication and testing.

    Configuration: Only requires a Server Port.

## Web-Server(HTTP)

    Purpose: Serves static files over HTTP.

    Configuration:

        Server Port: The port for the HTTP server (e.g., 80, 8080).

        Web Root Dir: Click "Browse..." to select the directory containing your web files (e.g., index.html, styles.css).

## Web-Server(HTTPS)

    Purpose: Provides secure web serving using SSL/TLS.

    Configuration:

        Server Port: The port for the HTTPS server (e.g., 443, 8443).

        Web Root Dir: Click "Browse..." to select the directory containing your web files.

        SSL Cert File: Click "Browse..." to select your SSL certificate file (e.g., server.pem).

        SSL Key File: Click "Browse..." to select your SSL private key file (e.g., key.pem).

## FTP-Server

    Purpose: Allows clients to transfer files using the FTP protocol.

    Configuration:

        Server Port: The port for the FTP server (e.g., 21).

        FTP Root Dir: Click "Browse..." to select the directory that will serve as the root for FTP operations.

    FTP Server Credentials:
    The FTP server currently uses hardcoded credentials for authentication:

        Username: ftpuser

        Password: ftppass

## Log-Area

The large text area at the bottom of the main content frame displays real-time logs from the server. This includes:

    Informational messages ([*], often in blue)

    Success messages ([+], often in green)

    Warning messages ([-], often in yellow)

    Error messages ([-], often in red)

## Troubleshooting

    "Could not bind to port..." error: This usually means the port is already in use by another application, or you don't have the necessary permissions to use that port (e.g., ports below 1024 often require root/administrator privileges). Try a different port number (e.g., 9999).

    "Web Root Directory is invalid or not set." / "FTP Root Directory is invalid or not set.": Ensure you have selected a valid, existing directory for the respective server mode before starting the server.

    "SSL Certificate/Key file is invalid or not set.": Verify that your .pem certificate and key files exist and are correctly formatted.

    Server not responding: Check the log area for any error messages. Ensure no firewall is blocking the chosen port.

    GUI icon not showing: Make sure Pillow is installed and the assets/icons8-server-40.png file is in the correct location relative to main.py.

## Contributing

Contributions are welcome! If you find a bug, have a feature request, or want to contribute code, please follow these guidelines:

    Report Bugs: Open an issue on the GitHub repository with a clear description of the bug, steps to reproduce it, and expected behavior.

    Suggest Features: Open an issue to propose new features or enhancements.

    Submit Pull Requests:

        Fork the repository.

        Create a new branch for your changes (git checkout -b feature/your-feature-name or bugfix/your-bug-name).

        Make your changes and ensure the code adheres to existing style.

        Write clear, concise commit messages.

        Push your branch and open a pull request.

## License

This project is licensed under The Unlicense - see the LICENSE file for details.
