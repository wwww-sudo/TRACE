#!/usr/bin/env python3

import os
import subprocess
import sys

# === Configuration ===
ENABLE_TRACE = True  # True to enable TRACE defense; False to run without defense

# Paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LIBMODBUS_DIR = os.path.join(SCRIPT_DIR, "libmodbus-2.9.3")
LIBMODBUS_LIB_DIR = os.path.join(LIBMODBUS_DIR, "src", ".libs")
SERVER_EXEC = os.path.join(LIBMODBUS_DIR, "tests", ".libs", "unit-test-server")
GDB_SCRIPT = os.path.join(SCRIPT_DIR, "TRACE_CFI.py") if ENABLE_TRACE else os.path.join(SCRIPT_DIR, "baseline.py")
GDB_COMMAND = "tracecfi" if ENABLE_TRACE else "baseline"


def check_file(path, description="file"):
    """Check if a file exists and is executable"""
    if not os.path.isfile(path):
        print(f"❌ Error: {description} '{path}' does not exist.")
        sys.exit(1)
    if not os.access(path, os.X_OK):
        print(f"❌ Error: {description} '{path}' is not executable.")
        sys.exit(1)


def launch_gdb_server():
    """Launch the target server under GDB with proper environment variables."""
    print("🚀 Launching GDB with TRACE_CFI..." if ENABLE_TRACE else "🚀 Launching GDB without TRACE...")

    # Check files
    check_file(SERVER_EXEC, "Server executable")
    check_file(GDB_SCRIPT, "GDB script")

    # Prepare environment
    env = os.environ.copy()
    if "LD_LIBRARY_PATH" in env:
        env["LD_LIBRARY_PATH"] = f"{LIBMODBUS_LIB_DIR}:{env['LD_LIBRARY_PATH']}"
    else:
        env["LD_LIBRARY_PATH"] = LIBMODBUS_LIB_DIR

    print(f"🌐 LD_LIBRARY_PATH set to: {env['LD_LIBRARY_PATH']}")
    print(f"🔗 Running: {SERVER_EXEC}")

    # GDB command
    gdb_cmd = [
        "gdb", "-q", SERVER_EXEC,
        "-ex", f"source {GDB_SCRIPT}",
        "-ex", GDB_COMMAND
    ]

    # Run GDB
    return subprocess.Popen(gdb_cmd, env=env)


def main():
    gdb_proc = launch_gdb_server()
    gdb_proc.wait()
    print("✅ Experiment completed.")


if __name__ == "__main__":
    main()


