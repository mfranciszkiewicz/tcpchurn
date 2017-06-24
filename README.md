# tcpchurn

`tcpchurn` monitors TCP accept, open and close kernel calls, issued by a process. This utility makes use of eBPF (extended Berkeley Packet Filters), a feature introduced to the Linux kernel in version 3.15.

The count of accept, open and close calls is partitioned by `[1., 5., 10., 30., 60., 120., 240., 500., 1200.]` [s] time windows. These values can be changed with the `-w/--windows`  parameter.

## Installation

1. Install the BPF Compiler Collection (BCC), as instructed [here](https://github.com/iovisor/bcc/blob/master/INSTALL.md).

2. Install python dependencies with pip:
    ```
    (venv) # pip install -r requirements.txt
    ```

## Usage

This tool requires elevated privileges. To monitor a PID, type:
```
(venv) # sudo python tcpchurn.py 30800
```

For all available options, run
```
python tcpchurn.py --help
```

## Example output

Refreshing a tab in Chromium (no `-c` flag):

```
(venv) # sudo python tcpchurn.py 30800

...

   1200.0   500.0   240.0   120.0    60.0    30.0    10.0     5.0     1.0    ALL
O       7       7       7       7       7       7       7       7       3      7
C       1       1       1       1       1       1       1       1       0      1
   1200.0   500.0   240.0   120.0    60.0    30.0    10.0     5.0     1.0    ALL
O       7       7       7       7       7       7       7       7       0      7
C       1       1       1       1       1       1       1       1       0      1
   1200.0   500.0   240.0   120.0    60.0    30.0    10.0     5.0     1.0    ALL
O       7       7       7       7       7       7       7       7       0      7
C       1       1       1       1       1       1       1       1       0      1
   1200.0   500.0   240.0   120.0    60.0    30.0    10.0     5.0     1.0    ALL
O       7       7       7       7       7       7       7       7       0      7
C       1       1       1       1       1       1       1       1       0      1
   1200.0   500.0   240.0   120.0    60.0    30.0    10.0     5.0     1.0    ALL
O      10      10      10      10      10      10      10       6       3     10
C       3       3       3       3       3       3       3       2       2      3
```
