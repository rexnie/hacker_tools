#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A tool for analyzing process memory mapping information in Linux systems.

This script provides functionality to:
1. Display virtual address (VA) to physical address (PA) mappings for processes
2. Parse /proc/<pid>/smaps for memory mapping information
3. Use /proc/<pid>/pagemap to obtain page frame numbers and flags
4. link: https://zhuanlan.zhihu.com/p/1910990041360102583

Author: Rex Nie
Date: 2023-03-23
"""

import argparse
import glob
import os
import sys
from pathlib import Path
from typing import List, Optional, Tuple

# Verify root privileges
if os.geteuid() != 0:
    print("This script requires root privileges. Please run with sudo or as root.")
    sys.exit(1)

# Get system page size
DEFAULT_PAGE_SIZE = os.sysconf("SC_PAGESIZE")
if DEFAULT_PAGE_SIZE <= 0:
    print("Failed to get system page size. Please check system configuration.")
    sys.exit(1)


def get_hugetlb_page_sizes() -> List[int]:
    """
    Get supported HugeTLB page sizes from the system.

    Returns:
        List[int]: List of supported HugeTLB page sizes in bytes.
    """
    hugetlb_page_sizes = []

    # Primary method: Check /sys/kernel/mm/hugepages
    hugetlbpages_dir = "/sys/kernel/mm/hugepages"
    if os.path.exists(hugetlbpages_dir):
        for entry in os.listdir(hugetlbpages_dir):
            if entry.startswith("hugepages-"):
                try:
                    size_kb = int(entry.split('-')[1].replace('kB', ''))
                    hugetlb_page_sizes.append(size_kb * 1024)
                except ValueError:
                    continue

    # Fallback method: Check /proc/meminfo
    if not hugetlb_page_sizes:
        try:
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    if line.startswith("Hugepagesize:"):
                        size_kb = int(line.split()[1])
                        hugetlb_page_sizes.append(size_kb * 1024)
                        break
        except (IOError, ValueError):
            pass

    if not hugetlb_page_sizes:
        print("Warning: Unable to determine HugeTLB page sizes. Using default 2MB.")
        hugetlb_page_sizes.append(2 * 1024 * 1024)

    return sorted(hugetlb_page_sizes)


def to_hex(value: int) -> str:
    """
    Convert an integer to its hexadecimal representation.

    Args:
        value (int): Integer value to convert.

    Returns:
        str: Hexadecimal representation of the input value.
    """
    return f"0x{value:x}"


def get_physical_address_and_flags(pid: int, vaddr: int, page_size: int) -> Optional[Tuple[int, str]]:
    """
    Map a virtual address to its physical address using /proc/[pid]/pagemap.

    Args:
        pid (int): Process ID
        vaddr (int): Virtual address
        page_size (int): Page size in bytes

    Returns:
        Optional[Tuple[int, str]]: Tuple of (physical_address, flags) or (None, None) if mapping fails
    """
    pagemap_file = f"/proc/{pid}/pagemap"
    if not os.access(pagemap_file, os.R_OK):
        print(f"Cannot access {pagemap_file}. Process may have terminated or permission denied.")
        return (None, None)

    offset = (vaddr // page_size) * 8

    try:
        with open(pagemap_file, "rb") as f:
            f.seek(offset)
            entry = int.from_bytes(f.read(8), byteorder='little', signed=False)

        # Extract page frame number and flags
        pfn = entry & 0x7FFFFFFFFFFFFF
        present = (entry >> 63) & 1
        swapped = (entry >> 62) & 1
        file_mapped = (entry >> 61) & 1

        flags = []
        if present:
            flags.append("Present")
        if swapped:
            flags.append("Swapped")
        if file_mapped:
            flags.append("File-mapped")
        else:
            flags.append("Anonymous")
        flags_str = ", ".join(flags) if flags else "None"

        if not present and not swapped:
            print(f"Virtual address {to_hex(vaddr)} is not present in RAM or swap, flags: {flags_str}")
            return (None, None)

        phys_addr = pfn * page_size if present else None
        return (phys_addr, flags_str)

    except (IOError, ValueError) as e:
        print(f"Error reading pagemap for address {to_hex(vaddr)}: {e}")
        return (None, None)

def check_page_info_for_pid(pid: int, sizes_to_print: List[int]) -> None:
    """
    Analyze and display virtual-to-physical address mappings for a specific process.

    Args:
        pid (int): Process ID to analyze
        sizes_to_print (List[int]): List of page sizes to check and display

    The function reads /proc/[pid]/smaps to find memory mappings and displays:
    - Virtual address ranges
    - Corresponding physical addresses
    - Page sizes and flags
    """
    smaps_file = f"/proc/{pid}/smaps"
    if not os.access(smaps_file, os.R_OK):
        return

    try:
        with open(f"/proc/{pid}/cmdline", "r") as f:
            cmdline = f.read().replace('\0', ' ').strip()[:50] or "(no cmdline info)"
    except IOError:
        cmdline = "(no cmdline info)"

    found_page = False
    vaddr_start = vaddr_end = kernel_page_size = None
    print(f"Process {pid} ({cmdline}) VA-PA page mapping:")

    try:
        with open(smaps_file, "r") as f:
            for line in f:
                if '-' in line.split()[0]:
                    # Process previous range if it used specified page sizes
                    if (found_page and vaddr_start is not None and 
                        vaddr_end is not None and kernel_page_size is not None):
                        for page_size in sizes_to_print:
                            if kernel_page_size == page_size:
                                size = vaddr_end - vaddr_start
                                if size % page_size == 0:
                                    print(f"VA: {to_hex(vaddr_start)}-{to_hex(vaddr_end)} "
                                          f"(Size: {size // 1024} kB, pagesize: {page_size // 1024} kB)")

                                    vaddr = vaddr_start
                                    while vaddr < vaddr_end:
                                        phys_addr, flags = get_physical_address_and_flags(
                                            pid, vaddr, DEFAULT_PAGE_SIZE)
                                        if phys_addr is not None:
                                            phys_end = phys_addr + page_size
                                            print(f"  VA {to_hex(vaddr)} -> "
                                                  f"PA {to_hex(phys_addr)}-{to_hex(phys_end)} [{flags}]")
                                        else:
                                            print(f"  VA {to_hex(vaddr)} -> No physical mapping [{flags}]")

                                        vaddr += page_size
                                break

                    # Parse new memory range
                    range_parts = line.split()[0].split('-')
                    vaddr_start = int(range_parts[0], 16)
                    vaddr_end = int(range_parts[1], 16)
                    kernel_page_size = None
                    found_page = False

                elif line.startswith("KernelPageSize:"):
                    size_kb = int(line.split()[1])
                    kernel_page_size = size_kb * 1024
                    if kernel_page_size in sizes_to_print:
                        found_page = True

    except IOError as e:
        print(f"Error reading {smaps_file}: {e}")


def main():
    """
    Main entry point for the memory mapping analysis tool.

    Provides command-line interface to:
    - Filter analysis by specific PID
    - Specify page sizes to analyze
    - Display VA-PA mappings for processes
    """
    parser = argparse.ArgumentParser(
        description="Analyze and display process memory mappings (VA-PA).")
    parser.add_argument('-p', '--pid', type=int,
                       help="Filter by specific PID. If not provided, analyzes all processes.")
    parser.add_argument('-s', '--size', type=int,
                       help="Specific page size to analyze (in bytes). If not provided, "
                            "analyzes all supported HugeTLB page sizes.")

    args = parser.parse_args()
    hugetlb_page_sizes = get_hugetlb_page_sizes()

    print("Analyzing process memory mappings (VA-PA)...")
    print(f"System page size: {DEFAULT_PAGE_SIZE // 1024} kB")
    print(f"Supported HugeTLB page sizes: {[size // 1024 for size in hugetlb_page_sizes]} kB")
    print("-" * 75)

    if args.pid:
        if not os.path.exists(f"/proc/{args.pid}"):
            print(f"Error: PID {args.pid} does not exist or is inaccessible.")
            sys.exit(1)
        pids = [args.pid]
    else:
        pids = sorted(
            int(pid) for pid in os.listdir("/proc")
            if pid.isdigit() and os.path.isdir(f"/proc/{pid}")
        )

    sizes_to_print = [args.size] if args.size else hugetlb_page_sizes

    for pid in pids:
        check_page_info_for_pid(pid, sizes_to_print)

    print("-" * 75)
    print("Analysis completed.")


if __name__ == "__main__":
    main()

