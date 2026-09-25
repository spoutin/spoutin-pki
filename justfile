# Default: list all available commands
default:
    @just --list

# Install all dependencies using uv
install:
    uv sync

# Run all unit tests
test:
    uv run pytest

# Run tests with verbose output
test-v:
    uv run pytest -v

# Run the wifi-enrollment service locally for development
dev:
    uv run uvicorn services.wifi_enrollment.server:app --host 127.0.0.1 --port 8000 --reload

# Build Debian (.deb) package
build-deb version="0.1.0" arch="amd64":
    ./scripts/build-deb.sh {{version}} {{arch}}

# Clean Python and pytest caches
clean:
    find . -type d -name "__pycache__" -exec rm -rf {} +
    find . -type d -name ".pytest_cache" -exec rm -rf {} +
