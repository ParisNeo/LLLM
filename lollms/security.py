from fastapi import HTTPException
from ascii_colors import ASCIIColors
from urllib.parse import urlparse
import socket
from pathlib import Path
from typing import List
import os
import re
import platform
import string

def check_access(lollmsElfServer, client_id):
    client = lollmsElfServer.session.get_client(client_id)
    if not client:
        raise HTTPException(status_code=400, detail=f"Not accessible without id")
    return client


def sanitize_based_on_separators(line):
    """
    Sanitizes a line of code based on common command separators.

    Parameters:
    - line (str): The line of code to be sanitized.

    Returns:
    - str: The sanitized line of code.
    """
    separators = ['&', '|', ';']
    for sep in separators:
        if sep in line:
            line = line.split(sep)[0]  # Keep only the first command before the separator
            break
    return line.strip()

def sanitize_after_whitelisted_command(line, command):
    """
    Sanitizes the line after a whitelisted command, removing any following commands
    if a command separator is present.

    Parameters:
    - line (str): The line of code containing the whitelisted command.
    - command (str): The whitelisted command.

    Returns:
    - str: The sanitized line of code, ensuring only the whitelisted command is executed.
    """
    # Find the end of the whitelisted command in the line
    command_end_index = line.find(command) + len(command)
    # Extract the rest of the line after the whitelisted command
    rest_of_line = line[command_end_index:]
    # Sanitize the rest of the line based on separators
    sanitized_rest = sanitize_based_on_separators(rest_of_line)
    # If anything malicious was removed, sanitized_rest will be empty, so only return the whitelisted command part
    if not sanitized_rest:
        return line[:command_end_index].strip()
    else:
        # If rest_of_line starts directly with separators followed by malicious commands, sanitized_rest will be empty
        # This means we should only return the part up to the whitelisted command
        return line[:command_end_index + len(sanitized_rest)].strip()


def sanitize_shell_code(code, whitelist=None):
    """
    Securely sanitizes a block of code by allowing commands from a provided whitelist,
    but only up to the first command separator if followed by other commands.
    Sanitizes based on common command separators if no whitelist is provided.

    Parameters:
    - code (str): The input code to be sanitized.
    - whitelist (list): Optional. A list of whitelisted commands that are allowed.

    Returns:
    - str: The securely sanitized code.
    """
    
    # Split the code by newline characters
    lines = code.split('\n')
    
    # Initialize the sanitized code variable
    sanitized_code = ""
    
    for line in lines:
        if line.strip():  # Check if the line is not empty
            if whitelist:
                for command in whitelist:
                    if line.strip().startswith(command):
                        # Check for command separators after the whitelisted command
                        sanitized_code = sanitize_after_whitelisted_command(line, command)
                        break
            else:
                # Sanitize based on separators if no whitelist is provided
                sanitized_code = sanitize_based_on_separators(line)
            break  # Only process the first non-empty line
    
    return sanitized_code


class InvalidFilePathError(Exception):
    pass


def sanitize_path(path: str, allow_absolute_path: bool = False, error_text="Absolute database path detected", exception_text="Detected an attempt of path traversal or command injection. Are you kidding me?"):
    """
    Sanitize a given file path by checking for potentially dangerous patterns and unauthorized characters.

    Args:
    -----
    path (str): The file path to sanitize.
    allow_absolute_path (bool, optional): Whether to allow absolute paths. Default is False.
    error_text (str, optional): The error message to display if an absolute path is detected. Default is "Absolute database path detected".
    exception_text (str, optional): The exception message to display if a path traversal, command injection, or unauthorized character is detected. Default is "Detected an attempt of path traversal or command injection. Are you kidding me?".

    Raises:
    ------
    HTTPException: If an absolute path, path traversal, command injection, or unauthorized character is detected.

    Returns:
    -------
    str: The sanitized file path.

    Note:
    -----
    This function checks for patterns like "....", multiple forward slashes, and command injection attempts like $(whoami). It also checks for unauthorized punctuation characters, excluding the dot (.) character.
    """    
    if not allow_absolute_path and (path.strip().startswith("/") or path.strip().startswith("\\")):
        raise HTTPException(status_code=400, detail=exception_text)

    if path is None:
        return path

    # Regular expression to detect patterns like "....", multiple forward slashes, and command injection attempts like $(whoami)
    suspicious_patterns = re.compile(r'(\.\.+)|(/+/)|(\$\(.*\))')

    if suspicious_patterns.search(str(path)) or ((not allow_absolute_path) and Path(path).is_absolute()):
        ASCIIColors.error(error_text)
        raise HTTPException(status_code=400, detail=exception_text)

    # Detect if any unauthorized characters, excluding the dot character, are present in the path
    unauthorized_chars = set('!"#$%&\'()*+,:;<=>?@[]^`{|}~')
    if any(char in unauthorized_chars for char in path):
        raise HTTPException(status_code=400, detail=exception_text)

    if not allow_absolute_path:
        path = path.lstrip('/').lstrip('\\')

    return path

    
def sanitize_path_from_endpoint(path: str, error_text: str = "A suspected LFI attack detected. The path sent to the server has suspicious elements in it!", exception_text: str = "Invalid path!") -> str:
    """
    Sanitize a given file path from an endpoint by checking for potentially dangerous patterns and unauthorized characters.

    Args:
    -----
    path (str): The file path to sanitize.
    error_text (str, optional): The error message to display if a path traversal or unauthorized character is detected. Default is "A suspected LFI attack detected. The path sent to the server has suspicious elements in it!".
    exception_text (str, optional): The exception message to display if an absolute path or invalid character is detected. Default is "Invalid path!".

    Raises:
    ------
    HTTPException: If an absolute path, path traversal, or unauthorized character is detected.

    Returns:
    -------
    str: The sanitized file path.

    Note:
    -----
    This function checks for patterns like "...." and multiple forward slashes. It also checks for unauthorized punctuation characters, excluding the dot (.) character.
    """

    if path is None:
        return path

    if path.strip().startswith("/") or path.strip().startswith("\\"):
        raise HTTPException(status_code=400, detail=exception_text)

    # Regular expression to detect patterns like "...." and multiple forward slashes
    suspicious_patterns = re.compile(r'(\.\.+)|(/+/)')

    # Detect if any unauthorized characters, excluding the dot character, are present in the path
    unauthorized_chars = set('!"#$%&\'()*+,:;<=>?@[]^`{|}~')
    if any(char in unauthorized_chars for char in path):
        raise HTTPException(status_code=400, detail=exception_text)

    if suspicious_patterns.search(path) or Path(path).is_absolute():
        ASCIIColors.error(error_text)
        raise HTTPException(status_code=400, detail=exception_text)

    path = path.lstrip('/').lstrip('\\')
    return path


def forbid_remote_access(lollmsElfServer, exception_text = "This functionality is forbidden if the server is exposed"):
    if not lollmsElfServer.config.force_accept_remote_access and lollmsElfServer.config.host!="localhost" and lollmsElfServer.config.host!="127.0.0.1":
        raise Exception(exception_text)

def validate_path(path, allowed_paths:List[str|Path]):
    # Convert the path to an absolute path
    abs_path = os.path.realpath(str(path))

    # Iterate over the allowed paths
    for allowed_path in allowed_paths:
        # Convert the allowed path to an absolute path
        abs_allowed_path = os.path.realpath(allowed_path)

        # Check if the absolute path starts with the absolute allowed path
        if abs_path.startswith(abs_allowed_path):
            return True

    # If the path is not within any of the allowed paths, return False
    return False

def is_allowed_url(url):
    # Check if url is legit
    parsed_url = urlparse(url)        
    # Check if scheme is not http or https, return False
    if parsed_url.scheme not in ['http', 'https']:
        return False
    
    hostname = parsed_url.hostname
    
    try:
        ip_address = socket.gethostbyname(hostname)
    except socket.gaierror:
        return False
    
    return not ip_address.startswith('127.') or ip_address.startswith('192.168.') or ip_address.startswith('10.') or ip_address.startswith('172.')


if __name__=="__main__":
    sanitize_path_from_endpoint("main")
    sanitize_path_from_endpoint("cat/main")
    print("Main passed")
    sanitize_path_from_endpoint(".../user")
    print("hi")
