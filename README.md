# netdrop
**Like AirDrop, but this runs on Python**.

After using the disgustingly slow file sharing over bluetooth "app" that Windows 10 has, a friend of mine (@MikenTNT) came up with this idea of **making something better in Python**.

Using **websockets**, it is able to share files at **7MB/s** (1000 times faster than the Windows 10 "app").

## Usage
```
usage: netdrop [-h] [-f FILE [FILE ...]] [--file FILE]

By default works in server mode, for client mode use -f or --file

optional arguments:
  -h, --help          show this help message and exit
  -f FILE [FILE ...]  Client mode: Multiple input files to share
  --file FILE         Client mode: Input file to share
```

## Supported systems

**Right now it only works on Windows** (tested on Windows 10 but it should run on any version that has *Python3* installed) **but the plan is to make it run on anything that has *Python3* installed on it**.
