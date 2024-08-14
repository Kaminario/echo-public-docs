import argparse


def parse() -> None:
    parser = argparse.ArgumentParser(description="Silk Instant Extract Echo Server")
    default_host = "0.0.0.0"
    default_host = "localhost"
    parser.add_argument(
        "--host",
        type=str,
        default=default_host,
        help=f"Host to listen on (default: {default_host})",
    )
    default_port = 8000
    parser.add_argument(
        "--port",
        type=int,
        default=default_port,
        help=f"Port to listen on (default: {default_port})",
    )
    return parser.parse_args()
