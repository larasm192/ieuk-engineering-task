import os
import tempfile
import pandas as pd
import pytest

from traffic_analyser import parse_log_file, LOG_PATTERN
from traffic_analyser import save_to_csv

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

def test_save_to_csv_creates_file_and_content(capsys):
    df = pd.DataFrame({
        'ip': ['1.2.3.4', '5.6.7.8'],
        'country': ['US', 'GB'],
        'datetime': ['2024-06-01T12:00:00', '2024-06-01T12:01:00'],
        'method': ['GET', 'POST'],
        'path': ['/index.html', '/submit'],
        'status': ['200', '404'],
        'size': ['123', '456'],
        'ua': ['Mozilla/5.0', 'curl/7.68.0'],
        'duration': ['100', '200']
    })
    with tempfile.NamedTemporaryFile(delete=False, suffix='.csv') as tmp:
        output_path = tmp.name

    try:
        save_to_csv(df, output_path)
        captured = capsys.readouterr()
        assert os.path.exists(output_path)
        assert "Data saved to" in captured.out

        loaded = pd.read_csv(output_path)
        pd.testing.assert_frame_equal(df, loaded)
    finally:
        os.remove(output_path)

def test_save_to_csv_empty_dataframe(capsys):
    df = pd.DataFrame(columns=['ip', 'country', 'datetime', 'method', 'path', 'status', 'size', 'ua', 'duration'])
    with tempfile.NamedTemporaryFile(delete=False, suffix='.csv') as tmp:
        output_path = tmp.name

    try:
        save_to_csv(df, output_path)
        captured = capsys.readouterr()
        assert os.path.exists(output_path)
        assert "Data saved to" in captured.out

        loaded = pd.read_csv(output_path)
        assert loaded.empty
        assert list(loaded.columns) == list(df.columns)
    finally:
        os.remove(output_path)


