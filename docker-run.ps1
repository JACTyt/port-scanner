# Convenience wrapper for running the port scanner Docker image on Windows.
# Usage: .\docker-run.ps1 --host <host> --ports 1-1024 [options]
#
# NOTE: On Windows/Mac, --network=host connects to the Docker VM network, not
# your host's LAN. To reach LAN hosts, use --network=bridge and specify the
# host's IP directly, or run natively with run.bat instead.

New-Item -ItemType Directory -Force -Path "$PWD\reports" | Out-Null

docker run -it --rm `
  --network=host `
  --cap-add=NET_RAW `
  -v "${PWD}/reports:/reports" `
  port-scanner @args
