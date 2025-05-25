import subprocess
import sys

def install_dependencies():
    """
    Installs the necessary Python dependencies for the NetWeaver GUI.
    Currently, this includes 'Pillow'.
    """
    dependencies = ["Pillow"]
    print("Attempting to install NetWeaver GUI dependencies...")

    for dep in dependencies:
        try:
            print(f"Installing {dep}...")
            # Use sys.executable to ensure pip associated with the current Python interpreter is used
            process = subprocess.run(
                [sys.executable, "-m", "pip", "install", dep],
                capture_output=True,
                text=True,
                check=True # Raise an exception for non-zero exit codes
            )
            print(f"Successfully installed {dep}.")
            # Print stdout and stderr for more detail if needed, but keep it concise for success
            # print(process.stdout)
        except subprocess.CalledProcessError as e:
            print(f"Error installing {dep}:")
            print(f"STDOUT: {e.stdout}")
            print(f"STDERR: {e.stderr}")
            print(f"Please try installing it manually: pip install {dep}")
            sys.exit(1) # Exit if an installation fails
        except Exception as e:
            print(f"An unexpected error occurred while installing {dep}: {e}")
            sys.exit(1)

    print("\nAll specified dependencies have been installed.")
    print("You can now run the NetWeaver GUI using: python main.py")

if __name__ == "__main__":
    install_dependencies()
