# logger.py

from datetime import datetime

def log_event(message):
    with open("webshield.log", "a") as log_file:
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        log_file.write(f"{timestamp} {message}\n")
