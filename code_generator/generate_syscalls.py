#! /usr/bin/python3

"""generate syscalls_table.cpp."""
import re
from typing import Dict, List, Tuple, TypedDict

import requests

SyscallNumberToName = Dict[int, str]
SyscallNameToParams = Dict[str, List[Tuple[str, str]]]


def download_and_parse_syscall_numbers() -> SyscallNumberToName:
    # ToDo: why is this only on spotify fork??
    source: str = requests.get(
        "https://raw.githubusercontent.com/spotify/linux/master/arch/x86/include/asm/unistd_64.h").text

    # Better source ?!
    # /usr/include/x86_64-linux-gnu/asm/unistd_64.h

    syscalls: SyscallNumberToName = {}

    syscall_number_pattern = r"#define __NR_.*?\s(?P<number>\d+)\n__(?:SC_COMP|SYSCALL)\(.*?, sys_(?P<name>.*?)[,\)]"
    for syscall_match in re.finditer(syscall_number_pattern, source):
        syscall_name = syscall_match["name"]
        if(not syscall_name.endswith("16") and not syscall_name.endswith("32")):
            syscalls[syscall_match["number"]] = syscall_name

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

    def fix_type(type: str) -> str:
        type = type.replace("__user", "")
        type = type.replace("old_", "")
        type = type.replace("u64", "uint64_t")
        type = type.replace("u32", "uint32_t")
        type = type.replace("umode_t", "mode_t")
        type = type.replace("qid_t", "int")
        type = type.replace("rwf_t", "int")

        # Unsupported:
        type = type.replace("cap_user_header_t", "int")
        type = type.replace("cap_user_data_t", "int")
        type = type.replace("key_serial_t", "int")
        type = type.replace("  ", " ")
        return type

    syscalls: SyscallNameToParams = {}
    for syscall_match in re.finditer(syscall_pattern, source):
        syscall_name = syscall_match["syscall"]
        if(syscall_name.endswith("16") or syscall_name.endswith("32")):
            continue

        parsed_params = []
        if syscall_match.group("params") != "void":
            for param in syscall_match.group("params").split(","):
                param = param.strip()
                # parameter names are optional
                if param.endswith(("*", "long", "int", "size_t")):
                    parsed_params.append((fix_type(param), ""))
                else:
                    match = re.match(variable_type_and_name, param)
                    parsed_params.append(
                        (fix_type(match.group('type')), match.group('name')))

        # fix strange alias
        if(syscall_name == 'mmap_pgoff'):
            syscall_name = 'mmap'

        if(syscall_name == 'symlink'):
            parsed_params[1] = ('const char*', 'linkpath')  # not "new"

        syscalls[syscall_name] = parsed_params

    # Missing in list... need a better source!
    # parse man pages?? there must be a better way.
    syscalls['arch_prctl'] = [("int", "code"), ("unsigned long", "addr")]

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
        if syscall_name in syscall_name_to_params:
            for p in syscall_name_to_params.get(syscall_name):
                cpp_params.append('{' + f'"{p[0]}", "{p[1]}"' + '}')
            s += ', '.join(cpp_params) + '}};'
        else:
            s += '}}; // parameters unknown'
        print(s)


def write_interface(syscall_name_to_params: SyscallNameToParams):
    print(f"// Generated via {__file__}")
    print("#include <linux/aio_abi.h>")
    print("#include <sys/user.h>")
    print("#include <unistd.h>")
    print("#include <cstdint>")
    print("#include <sys/epoll.h>")
    print("#include <sys/stat.h>")
    print("#include <fcntl.h>")
    print("#include <signal.h>")
    print("#include <mqueue.h>")
    # print("#include <keyutils.h>") - requires libkeyutils-dev
    print("#include <sys/uio.h>")
    # print("#include <sys/capability.h>") - requires libcap-dev
    print("using SyscallDataType = decltype(user_regs_struct{}.rax);")

    print("\nclass OnSyscall\n{")
    for name, params in syscall_name_to_params.items():
        cpp_params: List[str] = []
        for p in params:
            cpp_params.append(f"{p[0]} {p[1]}")
        cpp_params.append("SyscallDataType return_value")
        cpp_params: str = ', '.join(cpp_params)

        print(
            f'  virtual auto {name}({cpp_params}) -> void = 0;')
    print("};")


if __name__ == "__main__":
    syscall_number_to_name = download_and_parse_syscall_numbers()
    syscall_name_to_params = download_and_parse_syscall_params()
    #write_pretty_cpp_code(syscall_number_to_name, syscall_name_to_params)
    write_interface(syscall_name_to_params)
