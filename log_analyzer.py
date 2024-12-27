# log_analyzer.py

import os

def read_log_file(file_path):
    """Read the log file and return a list of log entries."""
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        return []
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            logs = file.readlines()
    except UnicodeDecodeError:
        # Fall back to UTF-16 if UTF-8 fails
        with open(file_path, 'r', encoding='utf-16') as file:
            logs = file.readlines()
    return [log.strip() for log in logs if log.strip()]

def extract_log_data(log_entry):
    """Extract IP, HTTP method, URL, and status code from a log entry."""
    try:
        parts = log_entry.split('"')  # Split by quotes to isolate the HTTP request part
        ip_and_details = parts[0].split()  # First part contains IP and other details
        request = parts[1].split()  # Second part is the HTTP method and URL
        status = int(parts[2].strip().split()[0])  # Status code is after the request
        ip = ip_and_details[0]
        method = request[0]
        url = request[1]
        return ip, method, url, status
    except (IndexError, ValueError):
        print(f"Skipping malformed log entry: {log_entry}")
        return None

def detect_suspicious_activity(log_entry):
    """Check for suspicious activity in the log entry."""
    data = extract_log_data(log_entry)
    if not data:
        return
    
    ip, method, url, status = data
    print(f"Extracted Data: IP={ip}, Method={method}, URL={url}, Status={status}")
    
    # Detect unauthorized access
    if status == 403:
        print(f"Suspicious Activity Detected: Unauthorized access attempt to {url} by {ip}")
    elif method == "DELETE":
        print(f"Suspicious Activity Detected: Unauthorized DELETE request by {ip}")
    elif status in [400, 404, 500]:
        print(f"Suspicious Activity Detected: Frequent errors from {ip}")
    else:
        print("No suspicious activity detected.")

def main():
    # Specify the path to your log file
    log_file = r"C:\Users\jeffr\log_analyzer\Sample_Logs.txt"
    
    print(f"Reading logs from: {log_file}")
    logs = read_log_file(log_file)
    
    if not logs:
        print("No logs to process. Exiting...")
        return
    
    print("\nProcessing log entries...\n")
    for log in logs:
        print(f"Processing log entry: {log}")
        detect_suspicious_activity(log)
        print("-" * 50)  # Separator for readability

if __name__ == "__main__":
    main()
