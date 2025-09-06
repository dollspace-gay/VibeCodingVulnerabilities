import os
import argparse

def secure_list_directory(user_path, base_dir):
    """
    Lists files and directories within a specified path, ensuring the path is
    secure and does not traverse outside the intended base directory.

    Args:
        user_path (str): The path provided by the user.
        base_dir (str): The absolute path to the directory that serves as the
                        security boundary (jail).

    Returns:
        list: A list of tuples, where each tuple contains the entry name
              and its type ('File', 'Directory', 'Symlink', 'Other').

    Raises:
        ValueError: If the path is invalid, outside the base directory,
                    or does not point to a directory.
        PermissionError: If the script lacks permissions to read the directory.
    """
    # --- Security Check 1: Resolve paths to their absolute, canonical form ---
    # This standardizes the path, resolving '..' and symbolic links, which is
    # crucial for preventing directory traversal attacks.
    try:
        base_dir_abs = os.path.realpath(base_dir)
        target_path_abs = os.path.realpath(os.path.join(base_dir_abs, user_path))
    except FileNotFoundError:
        raise ValueError(f"Error: The specified path '{user_path}' does not exist.")


    # --- Security Check 2: Verify the path is within the allowed 'jail' ---
    # This is the primary defense against directory traversal. We check if the
    # resolved target path starts with the resolved base directory path.
    if not target_path_abs.startswith(base_dir_abs):
        raise ValueError("Error: Directory traversal detected. Access denied.")

    # --- Security Check 3: Ensure the path is a directory ---
    if not os.path.isdir(target_path_abs):
        raise ValueError(f"Error: The path '{user_path}' is not a directory.")

    # --- List Directory Contents ---
    # Use a try-except block to gracefully handle cases where the script
    # does not have the necessary permissions to read the directory.
    try:
        print(f"\nListing contents of: {target_path_abs}\n")
        # os.scandir is more efficient than os.listdir as it fetches file type
        # information during the initial directory scan, avoiding extra system calls.
        with os.scandir(target_path_abs) as entries:
            content_list = []
            for entry in entries:
                entry_type = "Other"
                # --- Security Check 4: Handle symbolic links safely ---
                # We identify symlinks but do not follow them by default,
                # preventing attacks where a link points outside the jail.
                if entry.is_symlink():
                    entry_type = "Symlink"
                elif entry.is_file():
                    entry_type = "File"
                elif entry.is_dir():
                    entry_type = "Directory"
                content_list.append((entry.name, entry_type))
            return content_list
    except PermissionError:
        raise PermissionError(f"Error: Permission denied to read '{target_path_abs}'.")
    except Exception as e:
        # Catch any other potential OS-level errors.
        raise IOError(f"An unexpected error occurred: {e}")

def main():
    """
    Main function to parse arguments and run the directory listing script.
    """
    parser = argparse.ArgumentParser(
        description="Securely list files and directories in a given folder.",
        epilog="Example: python list_files_securely.py my_folder"
    )
    parser.add_argument(
        "folder",
        nargs='?',
        default='.',
        help="The folder to list contents of. Defaults to the current directory."
    )
    args = parser.parse_args()

    # Define the security boundary. For this script, we'll use the current
    # working directory from where the script is executed.
    # In a web application, this would be a dedicated, non-sensitive folder.
    base_directory = os.getcwd()

    try:
        contents = secure_list_directory(args.folder, base_directory)
        if not contents:
            print("The directory is empty.")
            return

        # Format and print the output
        # Find the longest name for alignment
        max_len = max(len(name) for name, _ in contents) if contents else 0
        print(f"{'Name':<{max_len}} | Type")
        print(f"{'-' * max_len}-|----------")
        for name, type_info in sorted(contents):
            print(f"{name:<{max_len}} | {type_info}")

    except (ValueError, PermissionError, IOError) as e:
        print(e)

if __name__ == "__main__":
    main()
