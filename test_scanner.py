from scan_engine.tcp_scanner import scan_tcp_range


target = "127.0.0.1"
start_port = 1
end_port = 1000

print(f"Scanning {target}...")
print(f"Ports: {start_port}-{end_port}")

open_ports = scan_tcp_range(
    target,
    start_port,
    end_port
)

print("Scan complete.")
print(f"Open ports: {open_ports}")