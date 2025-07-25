import re
from nginx_security_monitor.config_manager import ConfigManager


def parse_logs(log_file_path):
    config = ConfigManager.get_instance()

    structured_logs = []
    try:
        with open(log_file_path, "r") as log_file:
            for line in log_file:
                # Assuming the log format is a standard NGINX log format
                parts = line.split()
                if len(parts) > 0:
                    log_entry = {
                        "ip_address": parts[0],
                        "timestamp": parts[3][1:],  # Remove the leading '['
                        "request": parts[5][1:],  # Remove the leading '"'
                        "status_code": parts[8],
                        "response_size": parts[9],
                    }
                    structured_logs.append(log_entry)
    except Exception as e:
        print(f"Error parsing log file: {e}")

    return structured_logs
