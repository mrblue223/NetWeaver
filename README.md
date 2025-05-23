NetWeaver Server

![Alt text for your image](mrblue223/NetWeaver/NetWeaver.png)

NetWeaver is a multi-threaded TCP/Web/FTP server with a modern Tkinter-based GUI. It allows you to host generic TCP services, a basic HTTP web server, an HTTPS web server, or an FTP server.
Features

    Generic TCP Server: Listen for and handle raw TCP connections.

    Web Server (HTTP): Serve static files over HTTP from a specified root directory.

    Web Server (HTTPS): Serve static files over HTTPS, requiring SSL certificate and key files.

    FTP Server: Basic FTP server functionality (login, PWD, CWD, LIST, RETR, STOR) with a specified root directory.

    Modern GUI: A dark-themed graphical user interface for easy control and monitoring.

    Real-time Logging: View server activities and client interactions in a dedicated log area.

Installation

To run NetWeaver, you need Python 3 and the Pillow library.

    Ensure Python 3 is installed:
    If you don't have Python 3, you can download it from python.org.

    Install Dependencies using the provided script:
    Navigate to the directory where you saved install_dependencies.sh and NetWeaver.py in your terminal or command prompt, then run the installation script:

    bash install_dependencies.sh

    This script will check for Python and pip (Python's package installer) and then install the Pillow library, which is required for the GUI's icon functionality.

        Troubleshooting install_dependencies.sh:

            If you encounter permission errors, try running the script with sudo (on Linux/macOS):

            sudo bash install_dependencies.sh

            If pip3 is not found, the script will attempt to install it. If that fails, you might need to install it manually (e.g., sudo apt install python3-pip on Debian/Ubuntu).

Running the Server

Once the dependencies are installed, you can run the NetWeaver GUI application:

python3 NetWeaver.py

This will open the NetWeaver Server GUI window.
Using the Server Capabilities

The GUI provides a sidebar for server controls and mode selection, and a main content area for configuration and logging.
1. Server Controls

    Start Server: Click this button in the sidebar to start the server on the configured port and mode.

    Stop Server: Click this button to gracefully shut down the running server.

    Server Status: Click this button to display the current status of the server (running/stopped, mode, roots, etc.) in the log area.

2. Server Modes

You can select one of four server modes from the sidebar:

    Generic TCP:

        Purpose: For raw TCP communication. Clients can connect and send any data, and the server will respond with "ACK!".

        Configuration: Only requires a Server Port.

        Usage: Connect with a generic TCP client (e.g., netcat or a custom script) to the specified IP address and port.

    Web Server (HTTP):

        Purpose: Serves static web files (HTML, CSS, JS, images, etc.) over HTTP.

        Configuration:

            Server Port: The port for HTTP traffic (e.g., 80 or 8000).

            Web Root Dir: Crucial! Click "Browse..." to select the directory containing your website files (e.g., index.html). All files served will be relative to this directory.

        Usage: Open a web browser and navigate to http://<Your_Server_IP>:<Port>/ (e.g., http://localhost:8000/). Make sure you have an index.html file in your chosen web root for the default page.

    Web Server (HTTPS):

        Purpose: Serves static web files securely over HTTPS, encrypting communication.

        Configuration:

            Server Port: The port for HTTPS traffic (e.g., 443 or 8443).

            Web Root Dir: Same as HTTP mode, select your website files directory.

            SSL Cert File: Click "Browse..." to select your SSL certificate file (e.g., server.pem). This file contains your public certificate.

            SSL Key File: Click "Browse..." to select your SSL private key file (e.g., key.pem). This file must be kept secure.

            Note: You will need valid SSL certificate and key files. For testing, you can generate self-signed certificates (e.g., using OpenSSL).

        Usage: Open a web browser and navigate to https://<Your_Server_IP>:<Port>/ (e.g., https://localhost:8443/). Your browser might warn you about a self-signed certificate, which you'll need to accept to proceed.

    FTP Server:

        Purpose: Allows file transfers using the File Transfer Protocol.

        Configuration:

            Server Port: The port for FTP control connections (e.g., 21).

            FTP Root Dir: Click "Browse..." to select the directory that will serve as the root for FTP operations. Users will be confined to this directory and its subdirectories.

        Login Credentials:

            Username: ftpuser

            Password: ftppass

        Usage: Use an FTP client (e.g., FileZilla, ftp command-line tool, or a web browser that supports FTP) to connect to ftp://<Your_Server_IP>:<Port>/. Provide the specified username and password.

3. Log Area

The large text area at the bottom of the main content frame displays real-time logs of server activities, client connections, requests, and any errors or warnings. Messages are color-coded for easy readability:

    Blue: General information messages.

    Green: Success messages (e.g., file served, client authenticated).

    Red: Error messages.

    Yellow: Warning messages.

Important Notes

    Port Permissions: On Linux/macOS, binding to ports below 1024 (like 80, 443, 21) often requires root privileges. You might need to run the script with sudo if you intend to use these ports.

    Firewall: Ensure your system's firewall allows incoming connections on the chosen server port.

    Directory Traversal Protection: The Web and FTP servers include basic checks to prevent directory traversal attacks, ensuring clients cannot access files outside the specified root directories.

    FTP Active/Passive Mode: The FTP server supports both PORT (active) and PASV (passive) modes. Passive mode is generally preferred for clients behind firewalls.

    SSL Certificates: For HTTPS, ensure your .pem certificate and key files are correctly formatted and accessible.
