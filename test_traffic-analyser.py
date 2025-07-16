import os
import tempfile
import pandas as pd
import pytest

from traffic-analyser import parse_log_file, LOG_PATTERN

SAMPLE_LOG = (
    '192.168.1.1 - US - [2024-06-01T12:00:00] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0" 150\n'
    '10.0.0.2 - GB - [2024-06-01T12:01:00] "POST /submit HTTP/1.1" 404 567 "-" "curl/7.68.0" 200\n'
    '172.16.0.3 - FR - [2024-06-01T12:02:00] "HEAD /status HTTP/1.1" 301 89 "-" "python-requests/2.25.1" 50\n'
)

def test_parse_log_file_basic():
    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
        tmp.write(SAMPLE_LOG)
        tmp_path = tmp.name

    df = parse_log_file(tmp_path)
    os.remove(tmp_path)

    assert isinstance(df, pd.DataFrame)
    assert len(df) == 3
    assert set(df.columns) == {'ip', 'country', 'datetime', 'method', 'path', 'status', 'size', 'ua', 'duration'}
    assert df.iloc[0]['ip'] == '192.168.1.1'
    assert df.iloc[1]['country'] == 'GB'
    assert df.iloc[2]['method'] == 'HEAD'
    assert df.iloc[0]['path'] == '/index.html'
    assert df.iloc[1]['status'] == '404'
    assert df.iloc[2]['ua'] == 'python-requests/2.25.1'
    assert df.iloc[0]['duration'] == '150'

def test_parse_log_file_empty():
    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
        tmp.write('')
        tmp_path = tmp.name

    df = parse_log_file(tmp_path)
    os.remove(tmp_path)

    assert isinstance(df, pd.DataFrame)
    assert df.empty

def test_parse_log_file_invalid_lines():
    log_content = (
        'invalid log line\n'
        '192.168.1.1 - US - [2024-06-01T12:00:00] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0" 150\n'
    )
    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
        tmp.write(log_content)
        tmp_path = tmp.name

    df = parse_log_file(tmp_path)
    os.remove(tmp_path)

    assert isinstance(df, pd.DataFrame)
    assert len(df) == 1
    assert df.iloc[0]['ip'] == '192.168.1.1'