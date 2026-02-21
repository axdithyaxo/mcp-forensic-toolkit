import os
import hashlib
import datetime
import platform
import subprocess
from dotenv import load_dotenv
from mcp.server.fastmcp.server import FastMCP

# -------------------- Load Environment --------------------
# Load .env from parent directory (project root)
env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
load_dotenv(env_path)

SAFE_BASE = os.getenv("SAFE_BASE")
if not SAFE_BASE:
    raise RuntimeError("SAFE_BASE is not set. Please define it in your .env file.")

# -------------------- Helpers --------------------
def is_safe_path(path: str, base_dir: str = SAFE_BASE) -> bool:
    """
    Check if the given path is within the allowed base directory.
    Handles cross-platform path comparisons (case-insensitive on Windows).
    """
    abs_path = os.path.normcase(os.path.abspath(path))
    abs_base = os.path.normcase(os.path.abspath(base_dir))
    # Ensure base ends with separator to prevent partial matches (e.g., /safe vs /safety)
    if not abs_base.endswith(os.sep):
        abs_base += os.sep
    return abs_path.startswith(abs_base) or abs_path == abs_base.rstrip(os.sep)

# -------------------- MCP Server --------------------
mcp = FastMCP("ForensicToolkit")

# -------------------- Tools --------------------
@mcp.tool()
def scan_syslog(keyword: str) -> list[str]:
    """
    Scan system log files or unified logs for a given keyword.

    - On Linux: Reads from /var/log/syslog (or /var/log/messages as fallback)
    - On macOS: Uses `log show` to search unified system logs
    - On Windows: Uses PowerShell Get-WinEvent to search System and Application logs
    - Returns up to 100 relevant log lines

    Parameters:
        keyword (str): The case-insensitive keyword to search for.

    Returns:
        list[str]: Matching log lines (max 100), or an error message.
    """
    system = platform.system()

    try:
        if system == "Linux":
            # Try syslog first, fall back to messages
            log_path = "/var/log/syslog"
            if not os.path.exists(log_path):
                log_path = "/var/log/messages"
            if not os.path.exists(log_path):
                return [f"No log file found at /var/log/syslog or /var/log/messages."]
            with open(log_path, "r") as f:
                lines = [line for line in f if keyword.lower() in line.lower()]
                return lines[-100:] if lines else ["No matching entries found."]

        elif system == "Darwin":  # macOS
            result = subprocess.run(
                ["log", "show", "--predicate", f'eventMessage contains[c] "{keyword}"', "--last", "10m"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            if result.returncode != 0:
                return [f"log show error: {result.stderr.strip()}"]
            # Filter out header or empty lines
            lines = [
                line for line in result.stdout.splitlines()
                if line.strip() and not line.strip().startswith("Timestamp")
            ]
            return lines[-100:] if lines else ["No matching entries found."]

        elif system == "Windows":
            # Use PowerShell Get-WinEvent to query System and Application logs
            # Escape single quotes in keyword for PowerShell
            safe_keyword = keyword.replace("'", "''")

            # Query both System and Application logs for comprehensive coverage
            ps_script = f"""
$keyword = '{safe_keyword}'
$logs = @('System', 'Application')
$results = @()
foreach ($logName in $logs) {{
    try {{
        $events = Get-WinEvent -LogName $logName -MaxEvents 500 -ErrorAction SilentlyContinue |
            Where-Object {{ $_.Message -like "*$keyword*" }} |
            Select-Object -First 50
        foreach ($event in $events) {{
            $time = $event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
            $results += "$time [$logName] $($event.LevelDisplayName): $($event.Message -replace '\\r?\\n', ' ')"
        }}
    }} catch {{ }}
}}
$results | Select-Object -Last 100
"""
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_script],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            if result.returncode != 0:
                return [f"PowerShell error: {result.stderr.strip()}"]

            lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            return lines[-100:] if lines else ["No matching entries found."]

        else:
            return [f"Unsupported OS: {system}. Supported: Linux, macOS, Windows."]

    except Exception as e:
        return [f"Error reading logs: {str(e)}"]

@mcp.tool()
def file_metadata(path: str) -> dict:
    """
    Return metadata and SHA-256 hash for a file within the SAFE_BASE directory.
    """
    if not is_safe_path(path):
        return {"error": "Access denied: path is outside the allowed directory scope."}

    try:
        stat = os.stat(path)
        with open(path, "rb") as f:
            content = f.read()
        return {
            "size_bytes": stat.st_size,
            "created_at": datetime.datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified_at": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
def hash_directory(path: str) -> dict:
    """
    Recursively compute SHA-256 hashes for all files in a directory.
    """
    if not os.path.isdir(path):
        return {"error": "Provided path is not a directory."}

    results = {}
    for root, _, files in os.walk(path):
        for f in files:
            full_path = os.path.join(root, f)
            try:
                with open(full_path, "rb") as fp:
                    content = fp.read()
                    results[full_path] = hashlib.sha256(content).hexdigest()
            except Exception as e:
                results[full_path] = f"Error: {str(e)}"
    return results

@mcp.tool()
def correlate_file_and_logs(filename: str, keyword: str = "modified") -> dict:
    """
    Run scan_syslog and file_metadata together and return correlation context.

    Correlates system log events with the given file by:
    - Searching logs for the given keyword
    - Extracting file metadata (including modified timestamp)
    - Checking if the file's name appears in any relevant log entries

    Returns:
        dict: Metadata, log hits, and whether a correlation was found.
    """
    log_results = scan_syslog(keyword)
    file_info = file_metadata(filename)

    if "error" in file_info:
        return {"error": f"File error: {file_info['error']}"}

    mod_time = file_info.get("modified_at")
    basename = os.path.basename(filename).lower()

    # Match if filename appears in any log line
    correlation_found = any(basename in line.lower() for line in log_results)

    return {
        "filename": filename,
        "keyword": keyword,
        "file_modified_time": mod_time,
        "log_hits": log_results[:10],
        "correlation_found": correlation_found
    }

@mcp.tool()
def generate_forensic_report(filename: str, keyword: str = "modified") -> dict:
    """
    Generate a structured forensic report by combining file metadata and log analysis.

    This tool uses both `file_metadata` and `scan_syslog` to check whether the specified file's
    modification time aligns with log entries containing the provided keyword. It outputs
    a structured dictionary summarizing findings for programmatic consumption.

    Parameters:
        filename (str): Full path to the file to investigate.
        keyword (str): Keyword to search in system logs (default is 'modified').

    Returns:
        dict: A structured forensic report with file info, logs, and correlation status.
    """
    result = correlate_file_and_logs(filename, keyword)
    if "error" in result:
        return {
            "status": "error",
            "message": result["error"],
            "filename": filename,
            "keyword": keyword
        }

    return {
        "status": "ok",
        "filename": result["filename"],
        "keyword": result["keyword"],
        "file_modified_time": result["file_modified_time"],
        "log_hits": result["log_hits"],
        "correlation_found": result["correlation_found"]
    }

# -------------------- Prompts --------------------
@mcp.prompt("investigate-file")
def investigate_file_prompt(filename: str) -> str:
    return (
        f"You are a digital forensic analyst. Use the `file_metadata` tool on '{filename}' "
        f"to retrieve its size, creation time, modification time, and SHA-256 hash. "
        "Based on the timestamps and size, assess whether the file shows signs of tampering, "
        "suspicious timing, or unexpected characteristics."
    )

@mcp.prompt("triage-system-logs")
def triage_logs_prompt(keyword: str = "error") -> str:
    return (
        f"Search the system log for the keyword '{keyword}' using the `scan_syslog` tool. "
        "This works on Linux (syslog), macOS (unified logs), and Windows (Event Logs). "
        "Summarize the most relevant lines that indicate errors, warnings, or security-related events. "
        "Explain whether immediate action may be necessary."
    )

@mcp.prompt("correlate-log-and-file")
def correlate_log_and_file_prompt(filename: str, keyword: str = "modified") -> str:
    return (
        f"First, use `scan_syslog` to search for the keyword '{keyword}' in the system log. "
        f"Then use `file_metadata` on the file '{filename}'. "
        "Analyze whether the file modification time matches any suspicious log entries. "
        "If so, explain the correlation and what it may imply."
    )

@mcp.prompt("explain-correlation")
def explain_correlation_prompt(filename: str, keyword: str = "modified") -> str:
    return (
        f"Use the `correlate_file_and_logs` tool with filename '{filename}' and keyword '{keyword}'. "
        "Interpret the log hits and file metadata, and explain whether there's likely tampering or suspicious timing. "
        "Summarize your forensic reasoning in under 100 words."
    )

# -------------------- Resource --------------------
@mcp.resource("toolkit://about")
def about_toolkit() -> str:
    return (
        "MCP Forensic Toolkit - a secure, AI-integrated server for digital forensics.\n\n"
        "Key Features:\n"
        "- Log file triage using keyword-based search\n"
        "- File metadata and integrity checks via SHA-256\n"
        "- Cross-correlation between log entries and file activity\n\n"
        "Supported Platforms:\n"
        "- Linux: Reads from /var/log/syslog or /var/log/messages\n"
        "- macOS: Uses unified logging via 'log show'\n"
        "- Windows: Queries System and Application event logs via PowerShell\n\n"
        "Configuration:\n"
        "Set a safe base directory using the SAFE_BASE variable in a `.env` file to limit file access.\n"
        "Default base directory: ~/Desktop\n\n"
        "Use built-in prompts or tools via MCP Inspector or any LLM-compatible interface."
    )

# -------------------- Entry Point --------------------
if __name__ == "__main__":
    mcp.run()