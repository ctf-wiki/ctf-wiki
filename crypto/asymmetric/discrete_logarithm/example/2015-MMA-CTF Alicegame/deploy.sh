nohup socat tcp-l:9999,reuseaddr,fork exec:"python -u server.py" &
