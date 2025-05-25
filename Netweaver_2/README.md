# NetWeaver - Multi-threaded TCP/Web/FTP Server GUI

NetWeaver is a versatile, multi-threaded server application with a graphical user interface (GUI) built using Tkinter. It allows you to run a generic TCP server, an HTTP web server, an HTTPS secure web server, or an FTP server from a single application.

This README provides instructions on how to set up, run, and use the NetWeaver GUI.

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Project Structure](#project-structure)
- [Setup and Installation](#setup-and-installation)
- [Running the Application](#running-the-application)
- [Using the GUI](#using-the-gui)
    - [Server Controls](#server-controls)
    - [Server Modes](#server-modes)
        - [Generic TCP Server](#generic-tcp-server)
        - [Web Server (HTTP)](#web-server-http)
        - [Web Server (HTTPS)](#web-server-https)
        - [FTP Server](#ftp-server)
    - [Log Area](#log-area)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Generic TCP Server**: Listen for and handle raw TCP connections.
- **HTTP Web Server**: Serve static web content from a specified directory.
- **HTTPS Web Server**: Serve static web content securely over SSL/TLS.
- **FTP Server**: Basic FTP server for file listing, retrieving, and storing files (supports `USER`, `PASS`, `PWD`, `CWD`, `PORT`, `PASV`, `LIST`, `RETR`, `STOR`).
- **User-friendly GUI**: Start/stop server, select modes, configure directories and SSL certificates easily.
- **Real-time Logging**: Monitor server activity and client interactions directly in the GUI.
- **Modular Design**: Code is split into smaller, manageable files for easier development and debugging.

## Prerequisites

Before you begin, ensure you have the following installed:

- **Python 3.x**: NetWeaver is developed and tested with Python 3.
- **Pillow (PIL Fork)**: Required for handling image icons in the GUI.

You can install `Pillow` using pip:

```bash
pip install Pillow