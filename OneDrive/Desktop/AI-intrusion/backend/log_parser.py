import os
import pandas as pd

def parse_log_file(file_path):
    print(f"Checking file at: {os.path.abspath(file_path)}")
    print(f"File exists? {os.path.exists(file_path)}")
    
    parsed_records = []
    
    if not os.path.exists(file_path):
        print("ERROR: Log file not found!")
        return pd.DataFrame()

    with open(file_path, 'r') as file:
        for line_num, line in enumerate(file, 1):
            print(f"Reading line {line_num}: {line.strip()}")
            parts = line.split()
            if len(parts) >= 9:
                parsed_records.append({
                    'ip': parts[0],
                    'timestamp': parts[3].strip('[]'),
                    'method': parts[5].strip('"'),
                    'endpoint': parts[6],
                    'status': int(parts[8]),
                    'bytes': int(parts[9]) if parts[9].isdigit() else 0
                })
                
    return pd.DataFrame(parsed_records)

if __name__ == "__main__":
    log_file_path = "sample_logs/server_logs.txt"
    parsed_df = parse_log_file(log_file_path)
    
    print("\n--- Log Summary ---")
    print(f"Total Logs Parsed: {len(parsed_df)}")
    if not parsed_df.empty:
        print("\n--- Parsed Log Data Preview ---")
        print(parsed_df.head())
        print("\nStatus Code Distribution:")
        print(parsed_df['status'].value_counts())