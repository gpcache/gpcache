#! /usr/bin/python3

"""generate syscalls_table.cpp."""
import re
import requests
from typing import Dict, List, Tuple, TypedDict

SyscallNumberToName = Dict[int, str]
SyscallNameToParams = Dict[str, List[Tuple[str, str]]]


def download_and_parse_syscall_numbers() -> SyscallNumberToName:
    source: str = requests.get(
        "https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/asm-generic/unistd.h").text

    syscalls: SyscallNumberToName = {}

    syscall_number_pattern = r"#define __NR_.*? (?P<number>\d+)\n__(?:SC_COMP|SYSCALL)\(.*?, sys_(?P<name>.*?)[,\)]"
    for syscall_match in re.finditer(syscall_number_pattern, source):
        syscalls[syscall_match["number"]] = syscall_match["name"]

    return syscalls


def download_and_parse_syscall_params() -> SyscallNameToParams:
    source: str = requests.get(
        "https://raw.githubusercontent.com/torvalds/linux/master/include/linux/syscalls.h").text

    # all in one regex makes the regex unreadable, parse in two steps:
    # 1. fetch all syscalls
    # 2. parse syscall parameters

    syscall_pattern = re.compile(
        r"^asmlinkage long sys_(?P<syscall>.*?)\((?P<params>.*?)\);",
        re.MULTILINE | re.DOTALL)
    variable_type_and_name = r"^\s*(?P<type>.*?)\s*(?P<name>[^ *]*)\s*$"

    syscalls: SyscallNameToParams = {}
    for syscall_match in re.finditer(syscall_pattern, source):
        parsed_params = []
        if syscall_match.group("params") != "void":
            for param in syscall_match.group("params").split(","):
                param = param.strip()
                # parameter names are optional
                if param.endswith(("*", "long", "int", "size_t")):
                    parsed_params.append((param, ""))
                else:
                    match = re.match(variable_type_and_name, param)
                    parsed_params.append(
                        (match.group('type'), match.group('name')))

        syscalls[syscall_match["syscall"]] = parsed_params

    return syscalls


def write_pretty_cpp_code(
        syscall_number_to_name: SyscallNumberToName,
        syscall_name_to_params: SyscallNameToParams):
    for syscall_number, syscall_name in syscall_number_to_name.items():
        s = (
            f'syscall_params[{syscall_number}] = ' +
            '{' +
            f' "{syscall_name}", ' +
            '{'
        )
        cpp_params = []
        for p in syscall_name_to_params.get(syscall_name, ()):
            cpp_params.append('{' + f'"{p[0]}", "{p[1]}"' + '}')
        s += ', '.join(cpp_params) + '}};'
        print(s)


if __name__ == "__main__":
    syscall_number_to_name = download_and_parse_syscall_numbers()
    syscall_name_to_params = download_and_parse_syscall_params()
    write_pretty_cpp_code(syscall_number_to_name, syscall_name_to_params)
