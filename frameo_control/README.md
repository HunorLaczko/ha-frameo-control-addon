# Home Assistant Add-on: Frameo Control Backend

This add-on provides the backend service required for the **HA Frameo Control** integration to work. It handles all direct ADB communication with your Frameo device over USB or a network connection.

> [!IMPORTANT]
> This add-on must be installed and running **before** you install the main `HA Frameo Control` integration from HACS or manually.

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `server_port` | `5000` | The port the API server listens on. Change this if port 5000 is already in use. |

If you change the server port, make sure to also update the "Add-on Port" setting in the integration's options within Home Assistant.

For full installation and usage instructions, please see the main project repository:
[https://github.com/HunorLaczko/ha-frameo-control-addon](https://github.com/HunorLaczko/ha-frameo-control-addon)