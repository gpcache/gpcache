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
    kernal_internal_function_name: str
    params: List[Param]
    supported: bool = True


Syscalls = Dict[int, Syscall]


def download_and_parse_syscall_numbers() -> Syscalls:
    source: str = requests.get(
        "https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/entry/syscalls/syscall_64.tbl").text

    syscalls: Syscalls = {}

    syscall_number_pattern = (
        r"^(?P<number>\d*)\t+"
        r"(?P<abi>[a-z0-9]*)\t+"
        r"(?P<name>[a-z0-9_]*)"
        r"(\t+(?P<entry_point>[a-z0-9_]*))?$")
    for syscall_match in re.finditer(
            syscall_number_pattern,
            source,
            re.MULTILINE):

        if syscall_match["abi"] == "x32":
            continue

        syscall_id = int(syscall_match["number"])

        syscalls[syscall_id] = Syscall(
            syscall_id,
            syscall_match["name"],
            syscall_match["entry_point"],
            [])

        if(not syscall_match["entry_point"]):
            syscalls[syscall_id].supported = False

    return syscalls


def autofix(param: Param) -> Tuple[Param, bool]:
    supported = True

    param.cpptype = param.cpptype.replace("__user", "")
    param.cpptype = param.cpptype.replace("old_", "")
    param.cpptype = param.cpptype.replace("u64", "uint64_t")
    param.cpptype = param.cpptype.replace("u32", "uint32_t")
    param.cpptype = param.cpptype.replace("umode_t", "mode_t")
    param.cpptype = param.cpptype.replace("qid_t", "int")
    param.cpptype = param.cpptype.replace("rwf_t", "int")

    unsupported = (
        "cap_user_header_t cap_user_data_t key_serial_t mountpoint "
        "landlock_rule_type __aio_sigset io_uring_params pollfd "
        "sigaction __kernel_timeval __kernel_itimerval shmid_ds user_msghdr "
        "rusage utsname msgbuf msqid_ds sembuf linux_dirent rlimit sysinfo "
        "tms utimbuf sched_param __kernel_timex kexec_segment "
        "robust_list_head perf_event_attr iocb".split(" "))
    for u in unsupported:
        if u in param.cpptype:
            supported = False

    param.cpptype = param.cpptype.replace("  ", " ")

    if param.name == "sigmask":
        param.name = "SignMask"

    return (param, supported)


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

    param, supported = autofix(param)
    return supported, param


def download_and_parse_syscall_params(syscalls: Syscalls) -> None:
    # - parse man2 instead? Seems rather incomplete!
    # - Parse http://asm.sourceforge.net/syscall.html
    # - Parse linked c files? https://filippo.io/linux-syscall-table/

    def parse_header(syscalls: Syscalls, header: str):
        # all in one regex makes the regex unreadable, parse in two steps:
        # 1. fetch all syscalls
        # 2. parse syscall parameters

        syscall_pattern = re.compile(
            r"^asmlinkage long (?P<syscall>sys_.*?)\((?P<params>.*?)\);",
            re.MULTILINE | re.DOTALL)

        for syscall_match in re.finditer(syscall_pattern, header):
            kernal_internal_function_name = syscall_match["syscall"]

            def find_syscall_by_kernal_internal_function_name(
                    syscalls: Syscalls, kernal_internal_function_name: str):
                for syscall in syscalls.values():
                    if syscall.kernal_internal_function_name == kernal_internal_function_name:
                        return syscall.id
                return None

            syscall_id = find_syscall_by_kernal_internal_function_name(
                syscalls, kernal_internal_function_name)
            if syscall_id is None:
                # raise RuntimeError("Unknown syscall " + syscall_name)
                logging.warning(
                    "Unknown syscall " +
                    kernal_internal_function_name)
                continue

            syscall = syscalls[syscall_id]

            if syscall_match.group("params") != "void":
                for param_full_str in syscall_match.group("params").split(","):
                    supported, param = parse_param(param_full_str)
                    syscall.params.append(param)

                    if not supported:
                        syscall.supported = False

            # "new" is a bad idea in C++
            if len(syscall.params) >= 2 and syscall.params[1].name == 'new':
                syscall.params[1].name = 'new__'

    parse_header(syscalls, requests.get(
        "https://raw.githubusercontent.com/torvalds/linux/master/include/linux/syscalls.h").text)

    # mmap
    parse_header(syscalls, requests.get(
        "https://raw.githubusercontent.com/torvalds/linux/master/include/asm-generic/syscalls.h").text)


def write_event(file, syscalls: Syscalls):
    with open(file, 'w') as writer:
        writer.write("#pragma once\n")
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
            "  struct Event_Unsupported\n"
            "  {\n"
            "    SyscallDataType syscall_id;\n"
            "    SyscallDataType arg1;\n"
            "    SyscallDataType arg2;\n"
            "    SyscallDataType arg3;\n"
            "    SyscallDataType arg4;\n"
            "    SyscallDataType arg5;\n"
            "    SyscallDataType arg6;\n"
            "  };\n"
            "\n"
        )

        for syscall in filter(lambda sc: sc.supported, syscalls.values()):
            writer.write(
                f"  struct Event_{syscall.name}\n"
                "  {\n"
                f"    static SyscallDataType constexpr syscall_id = {syscall.id};\n")

            for pos, param in enumerate(syscall.params):
                var_name = param.name
                if not var_name:
                    var_name = f"unnamed{pos}"
                writer.write(f"    {param.cpptype} {var_name};\n")
            writer.write("    SyscallDataType return_value;\n"
                         "  };\n\n")

        for syscall in filter(lambda sc: not sc.supported, syscalls.values()):
            writer.write(f"  // Unsupported: {syscall}\n")

        writer.write("} // namespace\n")


def cast(var_type: str) -> str:
    if var_type == 'timer_t' or ('*' in var_type and '/*' not in var_type):
        return f"reinterpret_cast<{var_type}>"
    # if var_type != 'unsigned long':
    return f"static_cast<{var_type}>"
    # return ""


def write_event_wrapper(file, syscalls: Syscalls):
    with open(file, 'w') as writer:
        writer.write("#pragma once\n")
        writer.write(f"// Generated via {__file__}\n")
        for x in (
            "array variant linux/aio_abi.h sys/user.h unistd.h cstdint "
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
            "  using Syscall_Args = std::array<SyscallDataType, 6>;\n"
            "\n"
            "\n"
        )

        for syscall in filter(lambda sc: sc.supported, syscalls.values()):
            writer.write(
                f"  struct Syscall_{syscall.name} : public Syscall_Args\n"
                "  {\n"
                f"    Syscall_{syscall.name}(Syscall_Args args) : "
                "Syscall_Args(args) {}\n"
                "\n"
                f"    static SyscallDataType constexpr syscall_id = {syscall.id};\n"
                "\n")

            for pos, param in enumerate(syscall.params):
                if param.name:
                    writer.write(
                        f"    auto {param.name}() const -> {param.cpptype}\n"
                        "    {\n"
                        f"       return {cast(param.cpptype)}(operator[]({pos}));\n"
                        "    }\n"
                        "\n")
            writer.write("  };\n\n")

        for syscall in filter(lambda sc: not sc.supported, syscalls.values()):
            writer.write(f"  // Unsupported: {syscall}\n")

        writer.write("} // namespace\n")


def write_create_event(
        file, interface_file,
        syscalls: Syscalls):

    with open(file, 'w') as writer:
        writer.write(
            f"#include <{interface_file}>\n"
            "\n"
            "namespace gpcache\n"
            "{\n"
            "\n"
            "  // This variant compiles for ~42 seconds on my PC\n"
            "  using SyscallEvent = std::variant<\n"
            "    Event_Unsupported,\n"
            "    " +
            ",\n    ".join(
                f"Event_{syscall.name}" for syscall in filter(
                    lambda sc: sc.supported,
                    syscalls.values())) +
            "\n  >;\n"
            "  auto createEvent(SyscallDataType syscall_id, SyscallDataType arg1, SyscallDataType arg2, SyscallDataType arg3, SyscallDataType arg4, SyscallDataType arg5, SyscallDataType arg6) -> SyscallEvent\n"
            "  {\n"
            "    switch (syscall_id)\n"
            "    {\n"
        )

        for syscall in filter(lambda sc: sc.supported, syscalls.values()):
            s = (
                f'    case {syscall.id}: \n'
                f"      return Event_{syscall.name}\n"
                '      {\n'
            )

            for pos, param in enumerate(syscall.params):
                var_name = param.name
                if not var_name:
                    var_name = f"unnamed{pos}"

                s += (
                    f"      .{var_name} = "
                    f"{cast(param.cpptype)}(arg{pos+1}),\n"
                )

            s += (
                "      };\n"
            )
            writer.write(s)

        writer.write(
            "    } // switch\n"
            "\n"
            "    Event_Unsupported e;\n"
            "    e.syscall_id = syscall_id;\n"
            "    e.arg1 = arg1;\n"
            "    e.arg2 = arg2;\n"
            "    e.arg3 = arg3;\n"
            "    e.arg4 = arg4;\n"
            "    e.arg5 = arg5;\n"
            "    e.arg6 = arg6;\n"
            "    return e;\n"
            "  } // function\n"
            "\n"
            "} // namespace\n"
            ""
        )


def write_map(
        file, interface_file,
        syscalls: Syscalls):

    with open(file, 'w') as writer:
        writer.write(
            f"#include \"{interface_file}\"\n"
            "\n"
            "namespace Ptrace\n"
            "{\n"
            "\n"
            "  auto create_syscall_map() -> std::map<SyscallDataType, SyscallInfo> const {\n"
            "    thread_local static auto map = std::map<SyscallDataType, SyscallInfo>();\n"
            "    if(map.empty())\n"
            "    {\n"
            "\n")

        for syscall in syscalls.values():
            params = []
            for pos, param in enumerate(syscall.params):
                var_name = param.name
                if not var_name:
                    var_name = f"unnamed{pos}"

                params.append(
                    "{\"" + param.cpptype + "\", \"" + var_name + "\"}"
                )

            writer.write(
                f"      map[{syscall.id}] = SyscallInfo"
                "{" + f".syscall_id = {syscall.id}, .name = \"{syscall.name}\", .params = "
                "{ " + ", ".join(params) + "}};\n")

        writer.write(
            "    } // map.empty\n"
            "    return map;\n"
            "  } // create_syscall_map\n"
            "\n"
            "} // namespace\n"
            ""
        )


if __name__ == "__main__":
    repository_path = Path(os.path.dirname(__file__)).parent

    syscalls = download_and_parse_syscall_numbers()
    download_and_parse_syscall_params(syscalls)
    write_event(repository_path / 'old_obsolete' / 'SyscallEvent.h', syscalls)
    write_create_event(
        repository_path / 'old_obsolete' / 'SyscallEventCreator.cpp',
        'SyscallEventCreator.h',
        syscalls)
    write_event_wrapper(
        repository_path /
        'wrappers' /
        'ptrace' /
        'SyscallWrappers.h',
        syscalls)
    write_map(repository_path / 'wrappers' /
              'ptrace_linux_x64' / 'SyscallMap.cpp', '../ptrace.h', syscalls)
