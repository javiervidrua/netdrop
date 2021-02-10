# netdrop
**Like AirDrop, but this runs on Python**.

After using the disgustingly slow file sharing over bluetooth "app" that *Windows 10* has, a friend of mine (@MikenTNT) came up with this idea of **making something better in Python**.

Using **websockets**, it is able to share files at _**7MB/s**_ (1000 times faster than the *Windows 10* "app").

## Usage
```
usage: netdrop [-h] [-f FILE [FILE ...]] [--file FILE]

By default works in server mode, for client mode use -f or --file

optional arguments:
  -h, --help          show this help message and exit
  -f FILE [FILE ...]  Client mode: Multiple input files to share
  --file FILE         Client mode: Input file to share
```
