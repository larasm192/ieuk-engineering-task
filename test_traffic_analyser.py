import pandas as pd
import pytest
from traffic_analyser import (
    parse_log_file,
    top_ips,
    top_user_agents,
    top_paths,
    detect_suspicious_ips,
    requests_per_minute_per_ip,
    top_n_requests_per_minute
)

# Sample log line that matches your regex
SAMPLE_LOG = '''
192.168.0.1 - US - [12/07/2024:13:45:30] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0" 123
192.168.0.1 - US - [12/07/2024:13:46:00] "POST /submit HTTP/1.1" 200 2048 "-" "Mozilla/5.0" 456
10.0.0.1 - GB - [12/07/2024:13:45:30] "GET /home HTTP/1.1" 404 512 "-" "curl/7.58.0" 78
10.0.0.2 - GB - [12/07/2024:13:46:00] "GET /home HTTP/1.1" 200 1024 "-" "curl/7.58.0" 100
'''

@pytest.fixture
def sample_df(tmp_path):
    file_path = tmp_path / "sample.log"
    file_path.write_text(SAMPLE_LOG.strip())
    df = parse_log_file(file_path)
    df['datetime'] = pd.to_datetime(df['datetime'], format='%d/%m/%Y:%H:%M:%S')
    return df

def test_parse_log_file(sample_df):
    assert isinstance(sample_df, pd.DataFrame)
    assert len(sample_df) == 4
    assert set(sample_df.columns) >= {"ip", "country", "method", "path", "status", "ua", "duration"}

def test_top_ips(sample_df):
    result = top_ips(sample_df, 1)
    assert result.index[0] == "192.168.0.1"
    assert result.iloc[0] == 2

def test_top_paths(sample_df):
    result = top_paths(sample_df, 1)
    assert result.index[0] == "/home"
    assert result.iloc[0] == 2

def test_top_user_agents(sample_df):
    result = top_user_agents(sample_df, 1)
    assert result.index[0] == "Mozilla/5.0"
    assert result.iloc[0] == 2

def test_detect_suspicious_ips(sample_df):
    result = detect_suspicious_ips(sample_df, threshold=1)
    assert "192.168.0.1" in result.index
    assert result["192.168.0.1"] == 2

def test_requests_per_minute_per_ip(sample_df):
    rpm = requests_per_minute_per_ip(sample_df)
    assert isinstance(rpm, pd.Series)
    assert rpm.sum() == 4  # 4 total requests

def test_top_n_requests_per_minute(sample_df):
    result = top_n_requests_per_minute(sample_df, 2)
    assert isinstance(result, pd.Series)
    assert len(result) <= 2
    assert result.max() >= 1
