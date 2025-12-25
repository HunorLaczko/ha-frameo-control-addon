"""Frameo ADB Backend Server.

This Quart application serves as a bridge between Home Assistant and Frameo
devices via ADB (Android Debug Bridge). It maintains persistent connections
and exposes a REST API for device control.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass
from enum import StrEnum
from functools import partial
from pathlib import Path
from typing import Any

import usb1
from adb_shell.adb_device import AdbDeviceUsb
from adb_shell.adb_device_async import AdbDeviceTcpAsync
from adb_shell.auth.keygen import keygen
from adb_shell.auth.sign_pythonrsa import PythonRSASigner
from adb_shell.exceptions import (
    AdbConnectionError,
    AdbTimeoutError,
    UsbDeviceNotFoundError,
    UsbReadFailedError,
    UsbWriteFailedError,
)
from adb_shell.transport.usb_transport import UsbTransport
from quart import Quart, jsonify, request

# --- Configuration ---

ADB_KEY_PATH = "/data/adbkey"
ADDON_OPTIONS_PATH = "/data/options.json"
SERVER_HOST = "0.0.0.0"
DEFAULT_SERVER_PORT = 5000
DEFAULT_TRANSPORT_TIMEOUT = 9.0
USB_AUTH_TIMEOUT = 120.0
TCP_AUTH_TIMEOUT = 20.0
DEFAULT_TCP_PORT = 5555


def _load_addon_options() -> dict[str, Any]:
    """Load addon configuration options.

    Returns:
        Dictionary of addon options.

    """
    options_path = Path(ADDON_OPTIONS_PATH)
    if options_path.exists():
        try:
            return json.loads(options_path.read_text())
        except (json.JSONDecodeError, OSError) as err:
            logging.warning("Failed to load addon options: %s", err)
    return {}


def _get_server_port() -> int:
    """Get the configured server port.

    Returns:
        Server port number.

    """
    # First check environment variable (useful for testing)
    env_port = os.environ.get("SERVER_PORT")
    if env_port:
        try:
            return int(env_port)
        except ValueError:
            pass

    # Then check addon options
    options = _load_addon_options()
    return options.get("server_port", DEFAULT_SERVER_PORT)


# --- Logging Setup ---

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
_LOGGER = logging.getLogger(__name__)


class ConnectionType(StrEnum):
    """Connection type for ADB devices."""

    USB = "USB"
    NETWORK = "NETWORK"


@dataclass
class DeviceConnection:
    """Holds the current device connection state."""

    client: AdbDeviceUsb | AdbDeviceTcpAsync | None = None
    is_usb: bool = False

    @property
    def is_connected(self) -> bool:
        """Check if a device is connected and available."""
        return self.client is not None and self.client.available

    async def close(self) -> None:
        """Close the current connection if any."""
        if self.client is not None:
            try:
                if self.is_usb:
                    await _run_sync(self.client.close)
                else:
                    await self.client.close()
            except Exception as err:
                _LOGGER.warning("Error closing connection: %s", err)
            finally:
                self.client = None

    async def shell(self, command: str) -> str:
        """Execute a shell command on the connected device.

        Args:
            command: ADB shell command to execute.

        Returns:
            Command output.

        Raises:
            ConnectionError: If no device is connected.

        """
        if not self.is_connected:
            raise ConnectionError("Device is not connected or available")

        _LOGGER.info("Executing shell command: '%s'", command)

        if self.is_usb:
            return await _run_sync(self.client.shell, command)
        return await self.client.shell(command)


# --- Global State ---

_signer: PythonRSASigner | None = None
_connection = DeviceConnection()


# --- Helper Functions ---


async def _run_sync(func: Any, *args: Any, **kwargs: Any) -> Any:
    """Run a synchronous (blocking) function in an executor.

    Args:
        func: Synchronous function to run.
        *args: Positional arguments for the function.
        **kwargs: Keyword arguments for the function.

    Returns:
        Function result.

    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, partial(func, *args, **kwargs))


def _load_or_generate_keys() -> PythonRSASigner:
    """Load ADB keys from disk, or generate them if they don't exist.

    Returns:
        RSA signer for ADB authentication.

    """
    if not os.path.exists(ADB_KEY_PATH):
        _LOGGER.info("No ADB key found, generating a new one at %s", ADB_KEY_PATH)
        keygen(ADB_KEY_PATH)

    _LOGGER.info("Loading ADB key from %s", ADB_KEY_PATH)

    with open(ADB_KEY_PATH) as f:
        private_key = f.read()
    with open(f"{ADB_KEY_PATH}.pub") as f:
        public_key = f.read()

    return PythonRSASigner(public_key, private_key)


def _usb_auth_callback(device_client: Any) -> None:
    """Log a message when USB auth is needed.

    Args:
        device_client: USB device client (unused).

    """
    _LOGGER.info(
        "!!! ACTION REQUIRED !!! "
        "Please check your device's screen to 'Allow USB Debugging'."
    )


def _parse_power_state(dumpsys_output: str) -> dict[str, Any]:
    """Parse power state from dumpsys output.

    Args:
        dumpsys_output: Output from 'dumpsys power' command.

    Returns:
        Dictionary with is_on and brightness values.

    """
    is_on = "mWakefulness=Awake" in dumpsys_output
    brightness = 0

    for line in dumpsys_output.splitlines():
        if "mScreenBrightnessSetting=" in line:
            try:
                brightness = int(line.split("=")[1])
                break
            except (ValueError, IndexError):
                pass

    return {"is_on": is_on, "brightness": brightness}


# --- Quart Web Application ---

app = Quart(__name__)


@app.before_serving
async def startup() -> None:
    """Initialize the ADB signer before starting the server."""
    global _signer
    _signer = await _run_sync(_load_or_generate_keys)
    _LOGGER.info("Frameo ADB Server initialized and ready for connection requests")


# --- API Endpoints ---


@app.route("/devices/usb", methods=["GET"])
async def get_usb_devices() -> tuple[Any, int]:
    """Scan for and return connected USB ADB devices.

    Returns:
        JSON list of device serial numbers.

    """
    _LOGGER.info("Request received: GET /devices/usb")

    try:
        devices = await _run_sync(UsbTransport.find_all_adb_devices)
        serials = [dev.serial_number for dev in devices]
        _LOGGER.info("Discovered USB devices: %s", serials)
        return jsonify(serials), 200

    except UsbDeviceNotFoundError:
        _LOGGER.warning("No USB devices found during scan")
        return jsonify([]), 200

    except Exception as err:
        _LOGGER.exception("Error finding USB devices")
        return jsonify({"error": str(err)}), 500


@app.route("/connect", methods=["POST"])
async def connect_device() -> tuple[Any, int]:
    """Establish a connection to a Frameo device.

    Expects JSON body with connection details:
    - connection_type: "USB" or "Network"
    - serial: Device serial (for USB)
    - host: Device IP (for Network)
    - port: Device port (for Network, default 5555)

    Returns:
        JSON status response.

    """
    global _connection

    conn_details = await request.get_json()
    if not conn_details:
        return jsonify({"error": "Connection details not provided"}), 400

    conn_type = conn_details.get("connection_type", "USB").upper()
    _LOGGER.info("Connect request via %s: %s", conn_type, conn_details)

    try:
        # Close any existing connection
        await _connection.close()

        if conn_type == ConnectionType.USB:
            serial = conn_details.get("serial")
            if not serial:
                return jsonify({"error": "USB connection requires a serial number"}), 400

            client = AdbDeviceUsb(
                serial=serial,
                default_transport_timeout_s=DEFAULT_TRANSPORT_TIMEOUT,
            )
            await _run_sync(
                client.connect,
                rsa_keys=[_signer],
                auth_timeout_s=USB_AUTH_TIMEOUT,
                auth_callback=_usb_auth_callback,
            )
            _connection = DeviceConnection(client=client, is_usb=True)

        else:  # NETWORK
            host = conn_details.get("host")
            if not host:
                return jsonify({"error": "Network connection requires a host"}), 400

            port = int(conn_details.get("port", DEFAULT_TCP_PORT))

            client = AdbDeviceTcpAsync(
                host=host,
                port=port,
                default_transport_timeout_s=DEFAULT_TRANSPORT_TIMEOUT,
            )
            await client.connect(rsa_keys=[_signer], auth_timeout_s=TCP_AUTH_TIMEOUT)
            _connection = DeviceConnection(client=client, is_usb=False)

        identifier = conn_details.get("serial") or conn_details.get("host")
        _LOGGER.info("Successfully connected to device: %s", identifier)
        return jsonify({"status": "connected"}), 200

    except (
        AdbConnectionError,
        AdbTimeoutError,
        UsbDeviceNotFoundError,
        usb1.USBError,
        ConnectionResetError,
    ) as err:
        _LOGGER.error("Failed to connect to device: %s", err)
        await _connection.close()
        return jsonify({"error": f"Connection failed: {err}"}), 500

    except Exception as err:
        _LOGGER.exception("Unexpected error during connection")
        await _connection.close()
        return jsonify({"error": f"Unexpected error: {err}"}), 500


@app.route("/state", methods=["POST"])
async def get_state() -> tuple[Any, int]:
    """Get the current device state (screen on/off, brightness).

    Returns:
        JSON with is_on and brightness values.

    """
    _LOGGER.info("Request received: POST /state")

    try:
        output = await _connection.shell("dumpsys power")
        state = _parse_power_state(output)
        return jsonify(state), 200

    except ConnectionError as err:
        return jsonify({"error": str(err)}), 503

    except (
        AdbConnectionError,
        AdbTimeoutError,
        ConnectionResetError,
        usb1.USBError,
        UsbReadFailedError,
        UsbWriteFailedError,
    ) as err:
        _LOGGER.error("Device disconnected or connection failed: %s", err)
        await _connection.close()
        return jsonify({"error": "Device disconnected", "details": str(err)}), 503


@app.route("/shell", methods=["POST"])
async def run_shell_command() -> tuple[Any, int]:
    """Execute an arbitrary shell command on the device.

    Expects JSON body with:
    - command: Shell command to execute

    Returns:
        JSON with command result.

    """
    data = await request.get_json()
    command = data.get("command") if data else None

    if not command:
        return jsonify({"error": "Command not provided"}), 400

    _LOGGER.info("Executing shell command: '%s'", command)

    try:
        result = await _connection.shell(command)
        _LOGGER.info("Shell command result: '%s'", result.replace('\n', ' | '))
        return jsonify({"result": result}), 200

    except ConnectionError as err:
        return jsonify({"error": str(err)}), 503

    except (
        AdbConnectionError,
        AdbTimeoutError,
        ConnectionResetError,
        usb1.USBError,
        UsbReadFailedError,
        UsbWriteFailedError,
    ) as err:
        _LOGGER.error("Device disconnected or command failed: %s", err)
        await _connection.close()
        return jsonify({"error": "Device disconnected", "details": str(err)}), 503


@app.route("/tcpip", methods=["POST"])
async def enable_tcpip() -> tuple[Any, int]:
    """Enable wireless ADB debugging on the device.

    Requires an active USB connection.

    Returns:
        JSON with result.

    """
    _LOGGER.info("Request received: POST /tcpip")

    if not _connection.is_usb or not _connection.is_connected:
        return jsonify({"error": "A USB connection is required for this action"}), 400

    try:
        port = DEFAULT_TCP_PORT
        await _run_sync(
            _connection.client._open,
            destination=f"tcpip:{port}".encode("utf-8"),
            transport_timeout_s=None,
            read_timeout_s=10.0,
            timeout_s=None,
        )
        return jsonify({"result": f"TCP/IP enabled on port {port}"}), 200

    except (
        AdbConnectionError,
        AdbTimeoutError,
        ConnectionResetError,
        usb1.USBError,
        UsbReadFailedError,
        UsbWriteFailedError,
    ) as err:
        _LOGGER.error("Device disconnected during tcpip command: %s", err)
        await _connection.close()
        return jsonify({"error": "Device disconnected", "details": str(err)}), 503

    except Exception as err:
        _LOGGER.exception("ADB error on tcpip command")
        return jsonify({"error": str(err)}), 500


if __name__ == "__main__":
    server_port = _get_server_port()
    _LOGGER.info("Starting Frameo ADB Server on port %d", server_port)
    app.run(host=SERVER_HOST, port=server_port, debug=False)