[![build](https://github.com/jackburton79/ocs-agent/actions/workflows/ccpp.yml/badge.svg)](https://github.com/jackburton79/ocs-agent/actions/workflows/ccpp.yml)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/6c35f5798f2341b3b1c9d2cfac43b8a3)](https://app.codacy.com/gh/jackburton79/inventory-agent?utm_source=github.com&utm_medium=referral&utm_content=jackburton79/inventory-agent&utm_campaign=Badge_Grade_Settings)
[![CodeFactor](https://www.codefactor.io/repository/github/jackburton79/inventory-agent/badge)](https://www.codefactor.io/repository/github/jackburton79/inventory-agent)

# Inventory Agent

A lightweight, high-performance inventory agent compatible with **OCS Inventory NG** and **GLPI**, designed for Linux, FreeBSD, and other Unix-like systems. The software collects hardware and software information from a machine and either sends it to an inventory server or exports it locally in XML format.

## Features

* Compatible with **OCS Inventory NG** and **GLPI**.
* Written in **C++**, with a small footprint and low resource consumption.
* Supports Linux and FreeBSD platforms.
* Sends inventory data over HTTP/HTTPS.
* Exports inventory data locally as XML files.
* Supports HTTP Basic Authentication.
* Suitable for embedded environments and systems with limited resources.
* Minimal dependencies: OpenSSL, zlib, and TinyXML2.

## Overview

Inventory Agent was originally developed as a lightweight alternative to the official OCS Inventory NG Unix agent. It was specifically designed to inventory resource-constrained systems such as PXE-booted thin clients and embedded environments where the Perl-based official agent was impractical.

The application gathers information about:

* Operating system
* CPU
* Memory
* Storage devices and volumes
* Network interfaces
* Connected monitors
* Installed software
* Users and running processes (where supported)

## Installation

### Prerequisites

Ensure the following components are installed:

* GCC or Clang with C++ support
* OpenSSL
* zlib
* make

The project includes ![TinyXML2](https://github.com/leethomason/tinyxml2) and ![CivetWeb](https://github.com/civetweb/civetweb) as an embedded dependency.

### Build

    make                            # build the agent and the test programs
    make check                      # run the unit tests
    make install                    # install to /usr/local/bin (stripped)
    make install PREFIX=/usr DESTDIR=/tmp/pkg   # staged install, e.g. for packaging
    make install INSTALL_STRIP=     # install without stripping the symbols

The agent is optimized for size (`-Os`, with unused code removed at link time).
Use `make DEBUG=1` for a debug build and `make V=1` to see the full compiler command lines.
Use `make WEBSERVER=0` to build without the web server of the daemon mode (and without CivetWeb),
which gives a smaller binary. Run `make clean` when changing `DEBUG` or `WEBSERVER`.
The usual `CC`, `CXX`, `CFLAGS`, `CXXFLAGS`, `CPPFLAGS`, `LDFLAGS` and `LDLIBS` variables are honored.


## Usage

    -h, --help                         Print usage
    -c, --conf <config_file>           Specify configuration file
    -s, --server <server>              Specify OCSInventory/GLPI server url
                                       If the server needs authentication, use the standard syntax <user>:<password>@<host>
        --format <format>              Specify the inventory format: FORMAT_OCS or FORMAT_GLPI
    -l, --local <folder>               Save a local inventory in the specified file or folder
        --stdout                       Print inventory to stdout

    -t, --tag <TAG>                    Specify tag. Will be ignored by server if a value already exists
        --no-software                  Do not retrieve installed software (--nosoftware is still accepted)
        --no-assettag                  Do not include asset tag in inventory

        --agent-string <string>        Specify custom HTTP agent string

    -d, --daemon                       Runs continuously in background
    -w, --wait <s>                     Wait for the specified amount of seconds before building the inventory
                                       (not in daemon mode, where the first inventory runs after one minute)

        --no-ssl-check                 Don't check server ssl certificate
        --logger <backend>             Specify error log backend (STDERR / SYSLOG).
                                       Default is standard error if attached to a terminal, otherwise syslog.
    -v, --verbose                      Verbose mode
        --version                      Print version and exit

        --use-current-time-in-device-ID  Use current time in the device ID, instead of the BIOS Date.
                                         No need to use this option unless you know why you need it.

The -l and -s options are mutually exclusive.
If no server or output file is specified, either via the -s/-l option or via configuration file (option -c),
the program will exit without doing anything.

In one-shot mode the program exits with status 1 if the inventory could not be sent or saved.

### Examples

Print inventory to standard output:

    ocsinventory-agent --stdout

Send inventory to server http://ocsinventory-ng/ocsinventory:

    ocsinventory-agent --server http://ocsinventory-ng/ocsinventory

Use the configuration file /etc/ocsinventory-ng.conf:

    ocsinventory-agent --conf /etc/ocsinventory-ng.conf

Send inventory to server https://ocsinventory-ng/ocsinventory which requires http basic authentication:

    ocsinventory-agent --server https://user:password@ocsinventory-ng/ocsinventory

Save a local inventory to /var/tmp/inventoryFile.xml:

    ocsinventory-agent --local /var/tmp/inventoryFile.xml

Save a local inventory to /var/tmp/<device_id>.xml:

    ocsinventory-agent --local /var/tmp/

## Configuration file

The configuration file passed with `-c` contains one `key=value` pair per line.
Spaces around keys and values are ignored, as are empty lines and lines starting with `#` or `;`.
Options given on the command line take precedence over the configuration file.

The agent writes the generated device ID (`deviceID`) back to the configuration file,
creating it if needed (with mode 0600, since it may contain credentials).
Comments and the order of the existing lines are preserved.
The server given with `-s` is never written to the file.

| Key | Description |
|-----|-------------|
| `server` | Server URL, as for `-s` |
| `format` | `FORMAT_OCS` or `FORMAT_GLPI`, as for `--format` |
| `TAG` | Tag, as for `-t` |
| `no-software` | `true` to skip the installed software, as for `--no-software` |
| `no-assettag` | `true` to skip the asset tag, as for `--no-assettag` |
| `agent-string` | Custom HTTP agent string, as for `--agent-string` |
| `no_ssl_check` | `true` to skip the server certificate verification, as for `--no-ssl-check` |
| `schedule_interval` | Daemon mode: seconds between two inventories (default 86400, one day; minimum 60) |
| `httpd-port` | Daemon mode: port of the web server (default 62354); `0` disables it |
| `httpd-trust` | Daemon mode: addresses allowed to force an inventory, separated by commas or spaces |

Example:

    # Inventory server
    server = https://ocs.example.com/ocsinventory
    TAG = office

    # Daemon mode
    schedule_interval = 43200
    httpd-trust = 10.0.0.10, 10.0.0.11

## Daemon mode

With `-d` the agent runs in background: the first inventory is sent one minute after startup,
then every `schedule_interval` seconds. A systemd unit is available in `contrib/`.

Unless built with `WEBSERVER=0`, the agent also runs a small web server
(port 62354 by default, see `httpd-port`):

| URL | Description |
|-----|-------------|
| `/` | Status page |
| `/status` | Agent status, as plain text |
| `/info` | Version, status and time of the last inventory, as JSON |
| `/now` | Schedule an inventory immediately (at most one request per minute) |

`/now`, and the corresponding link on the status page, are only available from trusted addresses:
the local host, the addresses listed in `httpd-trust` and the addresses of the configured server.
