![](https://github.com/jackburton79/ocs-agent/workflows/build/badge.svg)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/6c35f5798f2341b3b1c9d2cfac43b8a3)](https://app.codacy.com/gh/jackburton79/ocs-agent?utm_source=github.com&utm_medium=referral&utm_content=jackburton79/ocs-agent&utm_campaign=Badge_Grade_Settings)
[![CodeFactor](https://www.codefactor.io/repository/github/jackburton79/ocs-agent/badge)](https://www.codefactor.io/repository/github/jackburton79/ocs-agent)
[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/jackburton79/ocs-agent.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/jackburton79/ocs-agent/context:cpp)

Linux lite inventory agent
=====
A couple of years ago, where I work, we started using [OCS Inventory NG](http://www.ocsinventory-ng.org), which
is a really useful application in enterprises. It allows system administrators to inventory servers and workstations,
in order to plan obsolescenses and investments.
In the last two years, we also started using [Thinstation](http://www.thinstation.org) to recycle old computers
as Citrix terminals, by booting them via PXE.
Unfortunately, the OCS Inventory Agent for Unix is written in Perl. The Perl interpreter is quite big (~16MB) and
can't be put into the Thinstation images without getting a performance hit on booting. Moreover, the agent doesn't
work on a system with a read only filesystem (actually, the filesystem is read-write, but changes are lost 
when the terminal is powered off, since it's a in-RAM filesystem).
So I decided to write a small agent in C++ to be able to inventory also those machines which I was not able to do with the official agent.
The agent is not complete yet, but it can already produce an inventory of the machine and send it to the 
OCSInventory server, or save it locally.
The compiled program weights around 500kb on disk, and only has zlib and openssl as dependency, which are already present on any Thinstation installation.
It also uses [tinyxml2](http://www.grinninglizard.com/tinyxml2), a very small and efficient XML parsing/writing library, linked statically into the executable.
This is not the official OCSInventory NG agent, which can be found here: https://github.com/OCSInventory-NG/UnixAgent

    Usage:
      -h, --help                         Print usage
      -c, --conf <config_file>           Specify configuration file
      -s, --server <server>              Specify OCSInventory server url
                                         If the server needs authentication, use the standard syntax <user>:<password>@<host>
      -l, --local <folder>               Don't send inventory, instead save a local copy in the specified file or folder
          --stdout                       Don't send inventory, print it to stdout
      -t, --tag <TAG>                    Specify tag. Will be ignored by server if a value already exists
          --nosoftware                   Do not retrieve installed software

          --agent-string <string>        Specify custom HTTP agent string

      -d, --daemonize                    Detach from running terminal
      -w, --wait <s>                     Wait for the specified amount of seconds before building the inventory

          --log <option>                 Specify error log output (STDERR / SYSLOG).
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
