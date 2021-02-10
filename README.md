# netdrop
**Like AirDrop, but this runs on Python**.

After using the disgustingly slow file sharing over bluetooth "app" that Windows 10 has, a friend of mine (@MikenTNT) came up with this idea of **making something better in Python**.

Using **websockets**, it is able to share files at **7.5MB/s** (1000 times faster than the Windows 10 "app").

**The goal wasn't to build the best file transfer tool, but to build one myself using websockets and Python, and learning a lot in the process (Done)**.

## Supported systems

**Right now it only works on Windows** (tested on Windows 10 but it should run on any version that has *Python3* installed) **but the plan is to make it run on anything that has *Python3* installed on it**.

## Usage
```
usage: netdrop [-h] [-f FILE [FILE ...]] [--file FILE]

By default works in server mode, for client mode use -f or --file

optional arguments:
  -h, --help          show this help message and exit
  -f FILE [FILE ...]  Client mode: Multiple input files to share
  --file FILE         Client mode: Input file to share
```

## How it works

### Server mode

Listens on a port for incomming connections, then downloads the files to the program directory.

### Client mode

Looks for active hosts in the subnet that have the service up and running.

The user selects the desired server and starts the file transmission.

## TODO

* Add name discovery feature
* Add encryption (SSL)

## License

MIT License

Copyright (c) 2021 Javier Vidal Ruano

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
