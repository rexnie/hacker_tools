#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
 @Description: This tools is used to print linux processes's virtual address(VA) and physical address(PA) mapping information.
                it uses /proc/<pid>/smaps to get each process's memory mappings(VAs)
                and uses /proc/<pid>/pagemap to parse VA to PFN, page flags.
 @Author: Rex Nie
 @Date: 2023-03-23 10:22:38

'''

import os
import sys
import argparse
import glob
from typing import List, Optional, Tuple
from pathlib import Path

# Check if the script is running with root privileges
if os.geteuid() != 0:
    print("This script requires root privileges. Please run with sudo or as root.")
    sys.exit(1)

# Get the system's default page size (usually 4KB, 16KB, or 64KB on ARM64)
DEFAULT_PAGE_SIZE = os.sysconf("SC_PAGESIZE")
if DEFAULT_PAGE_SIZE <= 0:
    print("Failed to get kernel default page size. Please check system configuration.")
    sys.exit(1)

# Function to get supported hugetlb page sizes in a portable way
def get_hugetlb_page_sizes() -> List[int]:
    """
    Retrieve supported hugetlb page sizes from /sys/kernel/mm/hugepages or /proc/meminfo.
    Returns a list of hugetlb page sizes in bytes.
    """
    hugetlb_page_sizes = []

    # Method 1: Check /sys/kernel/mm/hugepages for available sizes
    hugetlbpages_dir = "/sys/kernel/mm/hugepages"
    if os.path.exists(hugetlbpages_dir):
        for entry in os.listdir(hugetlbpages_dir):
            if entry.startswith("hugepages-"):
                # Extract size in kB (e.g., "hugepages-2048kB")
                size_kb_str = entry.split('-')[1].replace('kB', '')
                try:
                    size_kb = int(size_kb_str)
                    hugetlb_page_sizes.append(size_kb * 1024)  # Convert to bytes
                except ValueError:
                    continue

    # Method 2: Fallback to /proc/meminfo if /sys/kernel/mm/hugepages is unavailable
    if not hugetlb_page_sizes:
        try:
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    if line.startswith("Hugepagesize:"):
                        # Example line: "Hugepagesize:        2048 kB"
                        size_kb = int(line.split()[1])
                        hugetlb_page_sizes.append(size_kb * 1024)  # Convert to bytes
                        break
        except (IOError, ValueError):
            pass

    if not hugetlb_page_sizes:
        print("Warning: Could not determine hugetlb page sizes. Assuming 2MB.")
        hugetlb_page_sizes.append(2 * 1024 * 1024)  # Default to 2MB as a fallback

    return sorted(hugetlb_page_sizes)

# Function to convert a number to hexadecimal format
def to_hex(value: int) -> str:
    """
    Convert an integer to a hexadecimal string.
    """
    return f"0x{value:x}"

# Function to read physical address from /proc/[pid]/pagemap
def get_physical_address_and_flags(pid: int, vaddr: int, page_size: int) -> Optional[Tuple[int, str]]:
    """
    Map a virtual address to a physical address using /proc/[pid]/pagemap.
    Returns the physical address in bytes or None if mapping fails.
    """
    pagemap_file = f"/proc/{pid}/pagemap"
    if not os.access(pagemap_file, os.R_OK):
        print(f"Cannot read {pagemap_file}. Process might have exited or permission denied.")
        return (None, None)

    # Calculate the offset in the pagemap file
    offset = (vaddr // page_size) * 8

    try:
        with open(pagemap_file, "rb") as f:
            f.seek(offset)
            entry = int.from_bytes(f.read(8), byteorder='little', signed=False)

        # Extract PFN (physical frame number, lower 55 bits)
        pfn = entry & 0x7FFFFFFFFFFFFF

        # Extract flags based on man proc
        present = (entry >> 63) & 1  # Bit 63: Page present in RAM
        swapped = (entry >> 62) & 1  # Bit 62: Page in swap space
        file_or_anon = (entry >> 61) & 1  # Bit 61: File-mapped or shared anonymous page

        flags = []
        if present:
            flags.append("Present")
        if swapped:
            flags.append("Swapped")
        if file_or_anon:
            flags.append("File-mapped")
        else:
            flags.append("Anonymous")
        flags_str = ", ".join(flags) if flags else "None"

        if not present and not swapped:
            print(f"Virtual address {to_hex(vaddr)} is neither in RAM nor swapped, flags:{flags_str}")
            return (None, None)

        # Calculate physical address (only meaningful if present)
        phys_addr = pfn * page_size if present else None
        return (phys_addr, flags_str)

    except (IOError, ValueError) as e:
        print(f"Failed to read pagemap entry for virtual address {to_hex(vaddr)}: {e}")
        return (None, None)

# Function to parse /proc/[pid]/smaps and find page mappings
def check_page_info_for_pid(pid: int, sizes_to_print: List[int]) -> None:
    """
    Check if the given process uses specific page sizes and print virtual-to-physical address mappings.
    """
    smaps_file = f"/proc/{pid}/smaps"
    if not os.access(smaps_file, os.R_OK):
        return

    # Get the process command line (for display purposes)
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
                # Check for a new memory range (e.g., "7f8b5c000000-7f8b5e000000 rw-p ...")
                if '-' in line.split()[0]:
                    # Process the previous range if it used huge pages
                    if found_page and vaddr_start is not None and vaddr_end is not None and kernel_page_size is not None:
                        for hps in sizes_to_print:
                            if kernel_page_size == hps:
                                size = vaddr_end - vaddr_start
                                if size % hps == 0:
                                    print(f"VA: {to_hex(vaddr_start)}-{to_hex(vaddr_end)} (Size: {size // 1024} kB, pagesize: {hps // 1024} kB)")

                                    # Map each huge page in the range
                                    vaddr = vaddr_start
                                    while vaddr < vaddr_end:
                                        phys_addr, flags = get_physical_address_and_flags(pid, vaddr, DEFAULT_PAGE_SIZE)
                                        if phys_addr is not None:
                                            phys_end = phys_addr + hps
                                            print(f"  VA {to_hex(vaddr)} -> PA {to_hex(phys_addr)}-{to_hex(phys_end)} [{flags}]")
                                        else:
                                            print(f"  VA {to_hex(vaddr)} -> No physical mapping [{flags}]")

                                        vaddr += hps
                                break

                    # Start parsing a new memory range
                    range_parts = line.split()[0].split('-')
                    vaddr_start = int(range_parts[0], 16)
                    vaddr_end = int(range_parts[1], 16)
                    kernel_page_size = None
                    found_page = False

                # Check for KernelPageSize field
                elif line.startswith("KernelPageSize:"):
                    size_kb = int(line.split()[1])  # Extract size in kB
                    kernel_page_size = size_kb * 1024  # Convert to bytes
                    if kernel_page_size in sizes_to_print:
                        found_page = True

            # Process the last memory range
            if found_page and vaddr_start is not None and vaddr_end is not None and kernel_page_size is not None:
                for hps in sizes_to_print:
                    if kernel_page_size == hps:
                        size = vaddr_end - vaddr_start
                        if size % hps == 0:
                            print(f"VA: {to_hex(vaddr_start)}-{to_hex(vaddr_end)} (Size: {size // 1024} kB, pagesize: {hps // 1024} kB)")

                            vaddr = vaddr_start
                            while vaddr < vaddr_end:
                                phys_addr, flags = get_physical_address_and_flags(pid, vaddr, DEFAULT_PAGE_SIZE)
                                if phys_addr is not None:
                                    phys_end = phys_addr + hps
                                    print(f"  VA {to_hex(vaddr)} -> PA {to_hex(phys_addr)}-{to_hex(phys_end)} [{flags}]")
                                else:
                                    print(f"  VA {to_hex(vaddr)} -> No physical mapping [{flags}]")
                                vaddr += hps
                        break

    except IOError as e:
        print(f"Failed to read {smaps_file}: {e}")

def main():
    """
    Main function to print processes's VA-PA page mapping.
    Supports filtering by PID via command-line argument.
    """
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Print processes's VA-PA page mapping.")
    parser.add_argument('-p', '--pid', type=int, help="filter by PID. If not provided, print all processes.")
    parser.add_argument('-s', '--size', type=int, help="print specific page size in byte. If not provided, all supported hugetlb page sizes will print.")

    args = parser.parse_args()

    # Get supported hugetlb page sizes
    hugetlb_page_sizes = get_hugetlb_page_sizes()

    print("Print process's VA-PA page mapping...")
    print(f"Kernel default page size: {DEFAULT_PAGE_SIZE // 1024} kB")
    print(f"Supported hugetlb page sizes: {[size // 1024 for size in hugetlb_page_sizes]} kB")
    print("-" * 75)

    # Determine PIDs to print
    if args.pid:
        pids = [args.pid]
        if not os.path.exists(f"/proc/{args.pid}"):
            print(f"PID {args.pid} does not exist or is inaccessible.")
            sys.exit(1)
    else:
        # Get all numeric directories in /proc (representing PIDs)
        pids = sorted(
            int(pid) for pid in os.listdir("/proc")
            if pid.isdigit() and os.path.isdir(f"/proc/{pid}")
        )

    # If a specific page size is provided, use it instead of all supported hugetlb sizes
    if args.size:
        sizes_to_print = [args.size]
    else:
        sizes_to_print = hugetlb_page_sizes

    # print each PID's VA-PA page mapping
    for pid in pids:
        check_page_info_for_pid(pid, sizes_to_print)

    print("-" * 75)
    print("Print completed.")

if __name__ == "__main__":
    main()
