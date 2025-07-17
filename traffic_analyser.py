import re
import pandas as pd

LOG_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)'             
    r'\s-\s'                                  
    r'(?P<country>[A-Z]{2})'                  
    r'\s-\s'                                  
    r'\[(?P<datetime>[^\]]+)\]'               
    r'\s"'                                    
    r'(?P<method>GET|POST|HEAD)'              
    r'\s'                                     
    r'(?P<path>[^\s]+)'                       
    r'\sHTTP/1\.\d"'                          
    r'\s(?P<status>\d{3})'                    
    r'\s(?P<size>\d+)'                        
    r'\s"[^"]*"'                              
    r'\s"(?P<ua>[^"]+)"'                      
    r'\s(?P<duration>\d+)'                    
)

def parse_log_file(filepath, pattern=LOG_PATTERN):
    '''
    Parses a log file and returns a DataFrame with structured data.
    '''
    data = []
    with open(filepath, encoding='utf-8') as f:
        for line in f:
            match = pattern.search(line)
            if match:
                data.append(match.groupdict())
    return pd.DataFrame(data)

def save_to_csv(df, output_path):
    '''
    Saves the DataFrame to a CSV file.
    '''
    df.to_csv(output_path, index=False)
    print(f"Data saved to {output_path}")

def print_sample(df, n=5):
    '''
    Prints a sample of the DataFrame.
    '''
    print(df.head(n))
    print(f"Total records processed: {len(df)}")

def top_ips(df, n=10):
    '''
    Returns the top n IPs by request count.
    '''
    return df['ip'].value_counts().head(n)

def top_user_agents(df, n=10):
    '''
    Returns the top n User-Agents by request count.
    '''
    return df['ua'].value_counts().head(n)

def top_paths(df, n=10):
    '''
    Returns the top n Paths by request count.
    '''
    return df['path'].value_counts().head(n)

def detect_suspicious_ips(df, threshold=1000):
    '''
    Detects IPs with request counts above a specified threshold.
    '''
    return df["ip"].value_counts()[df["ip"].value_counts() > threshold]

def requests_per_minute_per_ip(df):
    '''
    Calculates number of requests per minute per IP.
    Returns a DataFrame indexed by [datetime, ip].
    '''
    df['datetime'] = pd.to_datetime(df['datetime'], format='%d/%m/%Y:%H:%M:%S')
    df.set_index('datetime', inplace=True)
    rpm = df.groupby([pd.Grouper(freq='min'), 'ip']).size()
    return rpm

def top_n_requests_per_minute(df, n=20):
    '''
    Returns the top 20 requests per minute.
    '''
    rpm = requests_per_minute_per_ip(df)
    rpm_df = rpm.reset_index(name='count')
    # Get max requests per minute for each IP
    top_n = rpm_df.groupby('ip')['count'].max().sort_values(ascending=False).head(n)
    return(top_n)

def main():
    '''
    Main function to parse the log file, save to CSV, and print statistics.
    '''
    log_path = 'sample-log.log'
    output_csv = 'traffic_data.csv'
    df = parse_log_file(log_path)
    save_to_csv(df, output_csv)
    print_sample(df)

    print("\nTop 20 IPs by request count:")
    print(top_ips(df, 20))
    print("\nSuspicious IPs (more than 1000 requests):")
    print(detect_suspicious_ips(df))
    print("\nTop 20 requests per minute per IP:")
    print(top_n_requests_per_minute(df, 20))
    print("\nTop 10 Paths by request count:")
    print(top_paths(df))
    print("\nTop 10 User-Agents by request count:")
    print(top_user_agents(df))

if __name__ == "__main__":
    main()