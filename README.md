The GUI
![Alt text for the image](NetWeaver/Netweaver_2/NetWeaver.png)

NetWeaver - Quick Start Guide

This guide provides a quick overview of how to get the NetWeaver GUI running and how to use it to host a simple website.
1. Install Dependencies

Before running the NetWeaver GUI, you need to install its required Python libraries. A convenient script has been provided for this purpose.

    Save the dependency installation script (e.g., install_dependencies.py) in the same directory as your NetWeaver project files.

    Open your terminal or command prompt.

    Navigate to the directory where you saved install_dependencies.py.

    Run the script using:

    python3 install_dependencies.py

    This will install Pillow, which is necessary for the GUI's icons.

2. Run the NetWeaver GUI

Once the dependencies are installed, you can launch the NetWeaver GUI.

    Ensure you have the assets folder with the icons8-server-40.png file in your project directory (as mentioned in the more detailed README).

    In your terminal or command prompt, navigate to the NetWeaver project's root directory (where main.py is located).

    Run the main application:

    python main.py

    The NetWeaver GUI window should now appear.

3. Host a Website (HTTP/HTTPS)

NetWeaver can function as a simple HTTP or HTTPS web server.
Hosting an HTTP Website:

    Select Mode: In the left sidebar of the NetWeaver GUI, click on "Web Server (HTTP)".

    Configure Port: In the main content area, enter a port number for your web server in the "Server Port" field (e.g., 8080).

    Set Web Root Directory:

        Click the "Browse..." button next to "Web Root Dir:".

        Select the folder on your computer that contains your website files (e.g., index.html, styles.css, images). This folder will be the root of your website.

    Start Server: Click the "Start Server" button in the left sidebar.

    Access Website: Once the log area shows messages indicating the server is listening, open a web browser and go to http://localhost:YOUR_PORT_NUMBER (replace YOUR_PORT_NUMBER with the port you entered, e.g., http://localhost:8080).

Hosting an HTTPS Website (Secure):

For HTTPS, you will need an SSL certificate and a private key file (both typically in .pem format).

    Select Mode: In the left sidebar, click on "Web Server (HTTPS)".

    Configure Port: Enter a port number for your HTTPS server (e.g., 8443).

    Set Web Root Directory: Similar to HTTP, click "Browse..." and select your website's root folder.

    Select SSL Certificate File:

        Click the "Browse..." button next to "SSL Cert File:".

        Select your SSL certificate file (e.g., server.pem).

    Select SSL Key File:

        Click the "Browse..." button next to "SSL Key File:".

        Select your SSL private key file (e.g., key.pem). This file must correspond to your certificate.

    Start Server: Click the "Start Server" button in the left sidebar.

    Access Website: Once the server is running, open a web browser and go to https://localhost:YOUR_PORT_NUMBER (e.g., https://localhost:8443). Your browser might show a warning about the certificate being self-signed or untrusted, which is normal for locally generated certificates.
