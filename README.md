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


Usage
===
    -h, --help                         Print usage
    -c, --conf <config_file>           Specify configuration file
    -s, --server <server>              Specify OCSInventory/GLPI server url
                                       If the server needs authentication, use the standard syntax <user>:<password>@<host>
        --format <format>              Specify the inventory format: FORMAT_OCS or FORMAT_GLPI
    -l, --local <folder>               Save a local inventory in the specified file or folder
        --stdout                       Print inventory to stdout

    -t, --tag <TAG>                    Specify tag. Will be ignored by server if a value already exists
        --nosoftware                   Do not retrieve installed software

        --agent-string <string>        Specify custom HTTP agent string

    -d, --daemonize                    Detach from running terminal
    -w, --wait <s>                     Wait for the specified amount of seconds before building the inventory

    --logger <backend>                 Specify error log backend (STDERR / SYSLOG).
                                       Default is standard error if attached to a terminal, otherwise syslog. 
    -v, --verbose                      Verbose mode
        --version                      Print version and exit

        --use-current-time-in-device-ID  Use current time in the device ID, instead of the BIOS Date.
                                         No need to use this option unless you know why you need it.

    The -l and -s option are mutually exclusive.
    If no server or output file is specified, either via the -s/-l option or via configuration file (option -c), the program will exit without doing anything.

    Examples:
      Print inventory to standard output :
        ocsinventory-agent --stdout

      Send inventory to server http://ocsinventory-ng/ocsinventory :
        ocsinventory-agent --server http://ocsinventory-ng/ocsinventory

      Use the configuration file /etc/ocsinventory-ng.conf :
        ocsinventory-agent --conf /etc/ocsinventory-ng.conf

      Send inventory to server https://ocsinventory-ng/ocsinventory which requires http basic authentication :
        ocsinventory-agent --server https://user:password@ocsinventory-ng/ocsinventory

      Save a local inventory to /var/tmp/inventoryFile.xml :
        ocsinventory-agent --local /var/tmp/inventoryFile.xml

      Save a local inventory to /var/tmp/<device_id>.xml :
        ocsinventory-agent --local /var/tmp/
