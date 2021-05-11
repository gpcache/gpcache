#! /usr/bin/python3

"""generate syscalls_table.cpp."""
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Final, List, Tuple

import os
import re
import requests
import logging


@dataclass
class Param:
    cpptype: str
    name: str


@dataclass
class Syscall:
    id: int
    name: str
    params: List[Param]
    supported: bool = True


Syscalls = Dict[int, Syscall]


def download_and_parse_syscall_numbers() -> Syscalls:
    # ToDo: why is this only on spotify fork??
    source: str = requests.get(
        "https://raw.githubusercontent.com/spotify/linux/master/arch/x86/include/asm/unistd_64.h").text

    # Switch here?!
    # https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl

    # Better source ?!
    # /usr/include/x86_64-linux-gnu/asm/unistd_64.h

    syscalls: Syscalls = {}

    syscall_number_pattern = (
        r"#define __NR_.*?\s(?P<number>\d+)\n"
        r"__(?:SC_COMP|SYSCALL)\(.*?, sys_(?P<name>.*?)[,\)]")
    for syscall_match in re.finditer(syscall_number_pattern, source):
        syscall_id = int(syscall_match["number"])
        syscall_name = syscall_match["name"]

        syscalls[syscall_id] = Syscall(syscall_id, syscall_name, [])

    return syscalls


def fix_type(cpptype: str) -> Tuple[str, bool]:
    supported = True

    cpptype = cpptype.replace("__user", "")
    cpptype = cpptype.replace("old_", "")
    cpptype = cpptype.replace("u64", "uint64_t")
    cpptype = cpptype.replace("u32", "uint32_t")
    cpptype = cpptype.replace("umode_t", "mode_t")
    cpptype = cpptype.replace("qid_t", "int")
    cpptype = cpptype.replace("rwf_t", "int")

    unsupported = (
        "cap_user_header_t",
        "cap_user_data_t",
        "key_serial_t",
        "mountpoint",
        "enum landlock_rule_type",
        "__aio_sigset",
        "io_uring_params")
    for u in unsupported:
        if u in cpptype:
            supported = False
            cpptype = cpptype.replace(u, "int /* unsupported */")

    cpptype = cpptype.replace("struct", "")  # this is not C
    cpptype = cpptype.replace("  ", " ")
    return (cpptype, supported)


def parse_param(s: str) -> Tuple[bool, Param]:
    """Parse string like 'const char x' into Param"""
    param = Param(s.strip(), "")

    variable_type_and_name: Final = r"^\s*(?P<type>.*?)\s*(?P<name>[^ *]*)\s*$"

    # It would be better to count one word from the left, ignoring const and *.
    if not param.cpptype.endswith(("*",
                                   "long",
                                   "int",
                                   "unsigned",
                                   "size_t",
                                   "aio_context_t")):
        if match := re.match(
                variable_type_and_name, param.cpptype):
            param.cpptype = match.group('type')
            param.name = match.group('name')

    param.cpptype, supported = fix_type(param.cpptype)
    return supported, param


def download_and_parse_syscall_params(syscalls: Syscalls) -> None:
    # - parse man2 instead? Seems rather incomplete!
    # - Parse http://asm.sourceforge.net/syscall.html
    # - Parse linked c files? https://filippo.io/linux-syscall-table/

    source: str = requests.get(
        "https://raw.githubusercontent.com/torvalds/linux/master/include/linux/syscalls.h").text

    # all in one regex makes the regex unreadable, parse in two steps:
    # 1. fetch all syscalls
    # 2. parse syscall parameters

    syscall_pattern = re.compile(
        r"^asmlinkage long sys_(?P<syscall>.*?)\((?P<params>.*?)\);",
        re.MULTILINE | re.DOTALL)

    for syscall_match in re.finditer(syscall_pattern, source):
        syscall_name = syscall_match["syscall"]

        # fix strange alias
        if(syscall_name == 'mmap_pgoff'):
            syscall_name = 'mmap'

        syscall_id = next((
            syscall_id for syscall_id,
            syscall in syscalls.items() if syscall.name == syscall_name), None)
        if not syscall_id:
            # raise RuntimeError("Unknown syscall " + syscall_name)
            logging.debug("Unknown syscall " + syscall_name)
            continue

        syscall = syscalls[syscall_id]

        if syscall_match.group("params") != "void":
            for param_full_str in syscall_match.group("params").split(","):
                supported, param = parse_param(param_full_str)
                syscall.params.append(param)

                if not supported:
                    syscall.supported = False

        # "new" is a bad idea for names
        if(syscall_name == 'symlink' and syscall.params[1].name == 'new'):
            syscall.params[1].name = 'linkpath'


def write_event(file, syscalls: Syscalls):
    with open(file, 'w') as writer:
        writer.write(f"// Generated via {__file__}\n")
        for x in (
            "variant linux/aio_abi.h sys/user.h unistd.h cstdint "
                "sys/epoll.h sys/stat.h fcntl.h signal.h mqueue.h "
                "sys/socket.h linux/time_types.h sys/uio.h").split(' '):
            writer.write(f"#include <{x}>\n")
        # writer.write("#include <keyutils.h>") - requires libkeyutils-dev
        # writer.write("#include <sys/capability.h>") - requires libcap-dev

        writer.write(
            "\n"
            "namespace gpcache {\n"
            "\n"
            "  using SyscallDataType = decltype(user_regs_struct{}.rax);\n"
            "\n"
        )

        for syscall in filter(lambda sc: sc.supported, syscalls.values()):
            writer.write(f"  struct Event_{syscall.name}\n"
                         "  {\n")
            for pos, param in enumerate(syscall.params):
                var_name = param.name
                if not var_name:
                    var_name = f"unnamed{pos}"
                writer.write(f"    {param.cpptype} {var_name};\n")
            writer.write("    SyscallDataType return_value;\n"
                         "  };\n\n")

        writer.write(
            "  using SyscallEvent = std::variant<\n    " +
            ",\n    ".join(
                f"Event_{syscall.name}" for syscall in filter(
                    lambda sc: sc.supported,
                    syscalls.values())) +
            "\n  >;\n")

        for syscall in filter(lambda sc: not sc.supported, syscalls.values()):
            writer.write(f"  // Unsupported: {syscall}\n")

        writer.write("} // namespace\n")


def write_create_event(
        file, interface_file,
        syscalls: Syscalls):

    def cast(var_type: str) -> str:
        if '*' in var_type and '/*' not in var_type:
            return f"reinterpret_cast<{var_type}>"
        return f"static_cast<{var_type}>"

    with open(file, 'w') as writer:
        writer.write(
            f"#include <{interface_file}>\n"
            "\n"
            "namespace gpcache\n"
            "{\n"
            "\n"
            "  auto createEvent(SyscallDataType syscall_id, SyscallDataType arg1, SyscallDataType arg2, SyscallDataType arg3, SyscallDataType arg4, SyscallDataType arg5, SyscallDataType arg6) --> SyscallEvent\n"
            "  {\n"
            "    switch (syscall_id)\n"
            "    {\n"
        )

        for syscall in filter(lambda sc: sc.supported, syscalls.values()):
            s = (
                f'    case {syscall.id}: \n'
                '    {\n'
                f"      Event_{syscall.name}" " e{};\n"
            )

            for pos, param in enumerate(syscall.params):
                var_name = param.name
                if not var_name:
                    var_name = f"unnamed{pos}"

                s += (
                    f"      e.{var_name} = "
                    f"{cast(param.cpptype)}(arg{pos+1});\n"
                )

            s += (
                "      return e;\n"
                "    }\n"
            )
            writer.write(s)

        writer.write(
            "  }\n"
            "\n"
            "} // namespace\n"
            ""
        )


if __name__ == "__main__":
    repository_path = Path(os.path.dirname(__file__)).parent

    syscalls = download_and_parse_syscall_numbers()
    download_and_parse_syscall_params(syscalls)
    write_event(repository_path / 'SyscallEvent.h', syscalls)
    write_create_event(
        repository_path / 'SyscallEventCreator.cpp',
        'SyscallEvent.h',
        syscalls)
