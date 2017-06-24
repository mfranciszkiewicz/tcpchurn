#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import ipaddress
import monotonic
import os
import socket
import struct
import sys
import time

from bcc import BPF
from collections import OrderedDict
from ctypes import c_uint8, c_uint16, c_uint32, c_uint64, cast, Structure, POINTER
from threading import Thread, Lock


ACCEPT = 0
CONNECT = 1
CLOSE = 2

SOURCE = "tcpchurn.c"
CFLAGS = ['-w']

TRACE_WINDOWS = [1., 5., 10., 30., 60., 120., 240., 500., 1200.]
TERM_WIDTH = 80


class RollingWindow(object):

    def __init__(self, windows=None):
        self.windows = windows or TRACE_WINDOWS
        self.windows.sort(reverse=True)

        self._window = []
        self._counters = OrderedDict([(w, 0) for w in self.windows])
        self._indexes = OrderedDict([(w, 0) for w in self.windows])
        self._total = 0
        self._lock = Lock()

    def insert(self, data):
        with self._lock:
            idx = len(self._window) - 1
            while idx >= 0 and data < self._window[idx]:
                idx -= 1

            self._window.insert(idx + 1, data)
            self._total += 1

    def update_window(self):
        with self._lock:
            self._update_window()

    def _update_window(self):
        now = monotonic.monotonic()
        last_idx = len(self._window) - 1
        d_idx = None

        for wsz in self.windows:
            idx = self._indexes[wsz]
            min_ts = now - wsz

            while idx <= last_idx:
                if self._window[idx][0] >= min_ts:
                    break
                idx += 1

            if d_idx is None:
                d_idx = idx
            self._indexes[wsz] = idx - d_idx
            self._counters[wsz] = last_idx - idx + 1

        if d_idx:
            self._window = self._window[d_idx:]

    @property
    def stats(self):
        return self._counters.values() + [self._total]


class EventHandler(object):

    def __init__(self, windows=None, ignore_private_dst=False):
        self._ignore_private_dst = ignore_private_dst
        self._open = RollingWindow(windows)
        self._closed = RollingWindow(windows)

    def on_ipv4(self, cpu, data, size):
        struct_p = cast(data, POINTER(IPv4Event))
        self.insert(struct_p.contents.data)

    def on_ipv6(self, cpu, data, size):
        struct_p = cast(data, POINTER(IPv6Event))
        self.insert(struct_p.contents.data)

    def insert(self, data):
        daddr = data[2]
        state = data[-2]

        if self._ignore_private_dst:
            try:
                if ipaddress.ip_address(unicode(daddr)).is_private:
                    return
            except Exception as e:
                sys.stderr.write("Invalid address {}: {}".format(daddr, e))
                return

        if state == CLOSE:
            self._closed.insert(data)
        else:
            self._open.insert(data)

    @property
    def windows(self):
        return self._open.windows

    @property
    def stats(self):
        self._open.update_window()
        self._closed.update_window()
        return self._open.stats, self._closed.stats


class StatsPrinter(Thread):

    def __init__(self, event_handler, clear_screen=False, interval=1.):
        super(StatsPrinter, self).__init__(target=self._print)
        self.daemon = True

        self.clear_screen = clear_screen
        self.interval = float(interval)

        self._event_handler = event_handler
        self._data_fmt = None

    def _print(self):
        columns = self._event_handler.windows + ['ALL']

        while True:
            if self.clear_screen:
                os.system('clear')

            opened, closed = self._event_handler.stats

            self._print_row(columns)
            self._print_row(opened, prefix="O")
            self._print_row(closed, prefix="C")

            time.sleep(self.interval)

    def _print_row(self, data, prefix=' '):
        c_cnt = len(data) - 1
        p_sz = len(prefix) if prefix else 0
        c_sz = TERM_WIDTH / len(data)
        lc_sz = TERM_WIDTH - p_sz - c_sz * c_cnt

        if not self._data_fmt:
            self._data_fmt = '{p}' + '{:>{sz}}' * c_cnt + '{:>{lsz}}\n'

        result = self._data_fmt.format(*data, p=prefix, sz=c_sz, lsz=lc_sz)
        sys.stdout.write(result)


class IPv4Event(Structure):

    _fields_ = [
        ("ts_us", c_uint64),
        ("saddr", c_uint32),
        ("daddr", c_uint32),
        ("sport", c_uint16),
        ("dport", c_uint16),
        ("pid", c_uint32),
        ("state", c_uint8)
    ]

    @property
    def data(self):

        saddr = struct.pack("I", self.saddr)
        daddr = struct.pack("I", self.daddr)

        return self.ts_us / 1000000., \
            socket.inet_ntop(socket.AF_INET, saddr), \
            socket.inet_ntop(socket.AF_INET, daddr), \
            self.sport, socket.ntohs(self.dport), \
            self.state, chr(4)


class IPv6Event(Structure):

    _fields_ = [
        ("ts_us", c_uint64),
        ("saddr", c_uint64 * 2),
        ("daddr", c_uint64 * 2),
        ("sport", c_uint16),
        ("dport", c_uint16),
        ("pid", c_uint32),
        ("state", c_uint8)
    ]

    @property
    def data(self):

        mask = (1 << 64) - 1
        saddr = struct.pack("2Q", self.saddr[0] >> 64, self.saddr[1] & mask)
        daddr = struct.pack("2Q", self.daddr[0] >> 64, self.daddr[1] & mask)

        return self.ts_us / 1000000., \
            socket.inet_ntop(socket.AF_INET6, saddr), \
            socket.inet_ntop(socket.AF_INET6, daddr), \
            self.sport, socket.ntohs(self.dport), \
            self.state, chr(6)


def run(pid, ignore_private_dst=None, windows=None, clear_screen=False, interval=None):

    cflags = CFLAGS + ['-DPID={}'.format(pid)]

    event_handler = EventHandler(windows, ignore_private_dst)
    stats_printer = StatsPrinter(event_handler, clear_screen, interval=interval)

    bpf = BPF(src_file=SOURCE, cflags=cflags)
    bpf["ipv4_events"].open_perf_buffer(event_handler.on_ipv4)
    bpf["ipv6_events"].open_perf_buffer(event_handler.on_ipv6)

    stats_printer.start()
    while True:
        bpf.kprobe_poll()


def main():

    parser = argparse.ArgumentParser(description="Trace TCP accept+open and close called by PID")
    parser.add_argument(
        "pid",
        type=int,
        help="Process ID"
    )
    parser.add_argument(
        "-c", "--clear",
        action='store_true',
        help="Clear screen on update"
    )
    parser.add_argument(
        "-p", "--ignore-private",
        action='store_true',
        help="Skip private dest IP addresses"
    )
    parser.add_argument(
        "-w", "--windows",
        nargs='+',
        help="Time window sizes (comma separated) [s]"
    )
    parser.add_argument(
        "-i", "--interval",
        type=float,
        help="Screen update interval [s]",
        default=1.
    )

    args = parser.parse_args()
    run(args.pid,
        args.ignore_private,
        args.windows,
        args.clear,
        args.interval)


if __name__ == '__main__':
    main()
