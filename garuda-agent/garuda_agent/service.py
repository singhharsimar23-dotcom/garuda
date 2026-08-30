"""
Systemd Service Generator for garuda-agent daemon.
Generates hardened systemd unit file with LimitCORE=0 and root execution for hardware counters.
"""

import argparse
import os
import shutil
import sys

SERVICE_TEMPLATE = """[Unit]
Description=GARUDA Host Telemetry Daemon
Documentation=https://github.com/singhharsimar23-dotcom/garuda
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart={exec_path} --config {config_path}
Restart=always
RestartSec=5
KillMode=mixed
TimeoutStopSec=10

# Hardening & Anti-Exfiltration
LimitCORE=0
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_RAWIO CAP_PERFMON CAP_DAC_OVERRIDE
AmbientCapabilities=CAP_SYS_ADMIN CAP_PERFMON

# Standard output and error
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""

DEFAULT_SERVICE_PATH = "/etc/systemd/system/garuda-agent.service"
DEFAULT_CONFIG_PATH = "/etc/garuda/config.toml"


def generate_service_content(
    exec_path: str = "/usr/local/bin/garuda-agent",
    config_path: str = DEFAULT_CONFIG_PATH,
) -> str:
    """Generate systemd service unit string."""
    return SERVICE_TEMPLATE.format(
        exec_path=exec_path,
        config_path=config_path,
    )


def install_service(
    output_path: str = DEFAULT_SERVICE_PATH,
    exec_path: str = None,
    config_path: str = DEFAULT_CONFIG_PATH,
) -> str:
    """Write generated systemd unit to systemd directory."""
    if exec_path is None:
        exec_path = shutil.which("garuda-agent") or f"{sys.executable} -m garuda_agent.daemon"

    content = generate_service_content(exec_path=exec_path, config_path=config_path)
    parent_dir = os.path.dirname(output_path)
    if parent_dir and not os.path.exists(parent_dir):
        os.makedirs(parent_dir, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    return content


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate systemd service unit for garuda-agent")
    parser.add_argument("--output", default=DEFAULT_SERVICE_PATH, help="Path to write unit file")
    parser.add_argument("--exec-path", default="/usr/local/bin/garuda-agent", help="Path to garuda-agent binary")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="Path to config.toml")
    parser.add_argument("--stdout", action="store_true", help="Print unit file to stdout instead of writing")
    args = parser.parse_args()

    content = generate_service_content(exec_path=args.exec_path, config_path=args.config)
    if args.stdout:
        print(content)
    else:
        try:
            install_service(output_path=args.output, exec_path=args.exec_path, config_path=args.config)
            print(f"Successfully generated systemd unit file at {args.output}")
        except PermissionError:
            print(f"Error: Permission denied writing to {args.output}. Run with sudo or use --stdout.", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
