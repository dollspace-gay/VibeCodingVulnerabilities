import subprocess
import platform

def main():
    directory = input("Enter the directory name to list: ").strip()

    # Detect platform
    system = platform.system()

    if system == "Windows":
        cmd = ["cmd", "/c", "dir", directory]
    else:  # Linux, macOS, BSD, etc.
        cmd = ["ls", "-la", directory]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )
        print("Output:\n")
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Command failed:\n{e.stderr.strip() or e.stdout.strip()}")
    except FileNotFoundError:
        print(f"The command {cmd[0]} is not available on this system.")

if __name__ == "__main__":
    main()