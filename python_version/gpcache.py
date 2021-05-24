#!/usr/bin/env python3
"""GPCache is a general purpose cache for pretty much any cachable tool you run repeatadly. See README for more info."""
import argparse
import hashlib
import logging
import os
import os.path
import yaml
import typing
from errno import EPERM
from logging import error

import ptrace
from ptrace import PtraceError
from ptrace.debugger import (NewProcessEvent, ProcessExecution,
                             ProcessExit, ProcessSignal, PtraceDebugger)
from ptrace.debugger.process import PtraceProcess
from ptrace.func_call import FunctionCallOptions
from ptrace.syscall import PtraceSyscall

info = logging.getLogger("gpcache").info
warn = logging.getLogger("gpcache").warning
log_debug = logging.getLogger("gpcache").debug


class Utils:
    @staticmethod
    def make_safe_filename(s: str):
        # https://stackoverflow.com/questions/7406102/create-sane-safe-filename-from-any-unsafe-string
        keepcharacters = (' ', '.', '_')
        return "".join(c for c in s if c.isalnum()
                       or c in keepcharacters).rstrip()

    @ staticmethod
    def read_c_string(process: PtraceProcess, addr) -> str:
        """Read C-String from process memory space at addr and return it."""
        data, truncated = process.readCString(addr, 5000)
        if truncated:
            return None  # fail in an obvious way for now
        return data.decode('ASCII')

    # Surprisingly common use case
    @ staticmethod
    def read_filename_from_syscall_parameter(
            syscall: PtraceSyscall, argument_name: str) -> str:
        cstring: str = Utils.read_c_string(
            syscall.process, syscall[argument_name].value)
        filename: str = os.fsdecode(cstring)
        return filename

    @ staticmethod
    def calculate_hash_of_str(string, digest_size=5):
        if isinstance(string, list):
            string = '_'.join(string)
        if isinstance(string, str):
            string = string.encode('ASCII')

        hash = hashlib.blake2b(digest_size=digest_size)
        hash.update(string)
        return hash.hexdigest()

    @ staticmethod
    def calculate_hash_of_file(file_path):
        # Reuse stat call? Usually there was a stat call before this.
        if not os.path.exists(file_path):
            return None

        # ToDo: investigate intention. cache directory content?
        if(os.path.isdir(file_path)):
            return "directory"

        # choose digest_size depending on filesize?!
        h = hashlib.blake2b(digest_size=16)

        with open(file_path, 'rb') as file:
            while True:
                # Reading is buffered, so we can read smaller chunks.
                chunk = file.read(h.block_size)
                if not chunk:
                    break
                h.update(chunk)

        return h.hexdigest()


class Inputs:
    """Holds collection of all inputs which should lead to the same output."""

    inputs = []

    # ToDo:
    # - cwd/pwd
    # - some env variables like SOURCE_DATE_EPOCH
    #   (never ending list... but adding everything would be overkill)
    # - uid, gid ?!

    def cache_object(self, action, result) -> None:
        self.inputs.append({'action': action, 'result': result})

    def cache_file(self, filename: str) -> None:
        if filename == "/dev/urandom":
            # bad idea trying to hash that... probably check for regular files?
            # design decision pending: how to trigger not cacheable throughout
            # the code?
            raise(Exception("Cannot cache: random number is used!"))
        else:
            self.cache_object(("filehash", filename),
                              Utils.calculate_hash_of_file(filename))

    def cache_stat(self, fd_or_filename) -> None:
        try:
            stat_result = os.stat(fd_or_filename)
        except FileNotFoundError:
            stat_result = None

        self.cache_object(("stat", fd_or_filename), stat_result)

    def cache_access(self, pathname, mode, result) -> None:
        self.cache_object(("access", pathname, mode), result)

    def print_summary(self) -> None:
        debug = log_debug
        for obj in self.inputs:
            debug("hash: %s", obj)


class Outputs:
    """Holds collection of all outputs which a program has produced."""

    files_to_write = {}  # path -> content
    # ToDo: intermixed stdout and stderr
    stdout: str = ""
    stderr: str = ""

    def write_file(self, filename, content) -> None:
        self.files_to_write[filename] += content

    def write_stdout(self, stdout: str) -> None:
        self.stdout = self.stdout + stdout

    def write_stderr(self, stderr: str) -> None:
        self.stderr += stderr

    def print_summary(self) -> None:
        log = log_debug

        log("stdout: %s", self.stdout)
        log("stderr: %s", self.stderr)

        for file, content in self.files_to_write.items():
            log("stat: %s = %s", file, content)


class FileBackend:
    """
    Stores cache in local files

    Uses directories to represent tree of all possible inputs.
    Maybe not the best idea. Works for now.
    """

    # ToDo: XDG / configurable
    CACHE_DIR: str = ".cache_dir"

    @staticmethod
    def yaml_from_file(filepath) -> typing.Any:
        if not os.path.exists(filepath):
            # warn(f"yaml_from_file({filepath})")
            return None
        with open(filepath, "r") as yamlfile:
            return yaml.safe_load(yamlfile)

    # max path length is limited (for some reason)
    @staticmethod
    def make_safe_short_filename(input, target_length=20) -> str:
        input = str(input)
        if len(input) > target_length:
            # no idea what a good number is
            digest_size = int(len(input) / 10)
            if digest_size > target_length - 5:
                digest_size = target_length - 5

            input = input[:(target_length - digest_size)] + \
                Utils.calculate_hash_of_str(input, digest_size)
        return Utils.make_safe_filename(input)

    @classmethod
    def ensure_yaml_content(cls, yamlfile, content) -> None:
        """ In case the directory is not sufficiently unique, the exact command is stored in yaml file """
        filecontent = cls.yaml_from_file(yamlfile)
        if not filecontent:
            os.makedirs(os.path.dirname(yamlfile), 0o777, True)
            with open(yamlfile, "w") as yamlfile:
                yaml.safe_dump(content, yamlfile)
        elif filecontent != content:
            warn("Mismatch of cached action vs real action.")
            warn("Program behaves unpredictably!")
            warn("This program cannot be cached!")
            warn(filecontent)
            warn(content)
            raise Exception("Mismatch of cached action vs real file content.")

    def store(self, inputs: Inputs, outputs: Outputs) -> str:
        """Stores data in cache and returns unique cache identifier"""

        path = self.CACHE_DIR

        for input in inputs.inputs:
            actionStr = str(input['action'])
            resultStr = str(input['result'])

            path += "/" + self.make_safe_short_filename(actionStr)
            self.ensure_yaml_content(f"{path}/action.yaml", actionStr)
            path += "/" + self.make_safe_short_filename(resultStr)
            self.ensure_yaml_content(f"{path}/result.yaml", resultStr)

        os.makedirs(path, 0o777, True)

        with open(f"{path}/outputs.yaml", "w") as outputs_yaml:
            yaml.safe_dump(outputs.files_to_write, outputs_yaml)
            yaml.safe_dump(outputs.stdout, outputs_yaml)
            yaml.safe_dump(outputs.stderr, outputs_yaml)

        return path

    def retrieve(self, command_line) -> Outputs:
        path = f"{self.CACHE_DIR}/command line/{self.make_safe_short_filename(str(command_line))}"
        cached = self.yaml_from_file(f"{path}/result.yaml")
        if not cached:
            info("command line is not cached")
            return None

        if cached != str(command_line):
            warn("Hash collision of cached command_line.")
            warn("Out of scope of proof of concept!")
            warn("This program cannot be cached!")
            return None

        # Descend directory tree as long as there is exactly one further
        # directory or outputs.yaml
        subfolders = [f.path for f in os.scandir(path) if f.is_dir()]
        if len(subfolders) == 1:
            path = f"/{subfolders[0]}"
            cached = self.yaml_from_file(f".{path}/action.yaml")
            if not cached:
                warn("error in cache")
                return None

            if cached[0] == "access":
                filename = cached[1]
                try:
                    stat_result = os.stat(filename)
                except FileNotFoundError:
                    stat_result = None
                warn(f"hash: '{stat_result}' vs '{cached[2]}'")
            elif cached[0] == "filehash":
                filename = cached[1]
                hash = Utils.calculate_hash_of_file(filename)
                warn(f"hash: {hash}")
            else:
                warn(f"todo: handle {cached} (key: {cached[0]})")
        pass

    def clear(self) -> None:
        pass


O_READONLY: int = 0
O_CLOEXEC: int = 0o2000000


class FiledescriptorManager:
    """For tracking and especially debugging file descriptor access."""

    fd_to_file_and_state = {}

    def __init__(self):
        self.fd_to_file_and_state[0] = {
            "filename": 0, "state": "open", "source": ["default"]}
        self.fd_to_file_and_state[1] = {
            "filename": 1, "state": "open", "source": ["default"]}
        self.fd_to_file_and_state[2] = {
            "filename": 2, "state": "open", "source": ["default"]}

    def print_fd(self, fd) -> None:
        log = log_debug

        log_debug(f"file desciptor {fd}:")
        # ToDo wrap all access and allow readonly array access for
        # FiledescriptorManager?
        file_and_state = self.fd_to_file_and_state[fd]
        log("---------------")
        log(
            f"filename: {file_and_state['filename']}")
        log(f"state: {file_and_state['state']}")
        for src in file_and_state['source']:
            log(f"action: {src}")
        log("---------------")

    def print_all(self) -> None:
        log = log_debug

        log("Known file desciptors:")
        for fd, file_and_state in self.fd_to_file_and_state.items():
            log("---------------")
            log(f"{fd}")
            log(f"filename: {file_and_state['filename']}")
            log(f"state: {file_and_state['state']}")
            for src in file_and_state['source']:
                log(f"action: {src}")

    def open(self, fd, file, source) -> None:
        if fd in self.fd_to_file_and_state:
            # move to some sort of history
            pass

        self.fd_to_file_and_state[fd] = {
            "filename": file, "state": "open",
            "source": [f"open via {source}"]}

    def close(self, fd, source) -> None:
        if fd not in self.fd_to_file_and_state:
            self.print_all()
            raise Exception(
                f"closing unknown fd {fd}")

        if self.fd_to_file_and_state[fd]["state"] == "closed":
            self.print_all()
            raise Exception(
                f"closing closed fd {fd}")

        self.fd_to_file_and_state[fd]["state"] = "closed"
        self.fd_to_file_and_state[fd]["source"].append(f"close via {source}")

    def get_filename(self, fd, source) -> None:
        if fd not in self.fd_to_file_and_state:
            self.print_all()
            raise Exception(
                f"retrieving unknown fd {fd}")

        if self.fd_to_file_and_state[fd]["state"] != "open":
            self.print_all()
            raise Exception(f"retrieving closed fd {fd} "
                            f"=> {self.fd_to_file_and_state[fd]}")

        self.fd_to_file_and_state[fd]["source"].append(
            f"get_filename via {source}")
        return self.fd_to_file_and_state[fd]["filename"]


class SyscallListener:
    # In theory this class could be made ptrace independent.
    # But thats a huge amount of wrappers.
    # And what's even the point? This handles Linux specific syscalls anyway.

    filedescriptors = FiledescriptorManager()
    inputs: Inputs
    outputs: Outputs

    def __init__(self, verbose):
        self.verbose = verbose

        self.inputs = Inputs()
        self.outputs = Outputs()

    # Terrible design. Pass Inputs from outside?!
    def set_command_line(self, command_line):
        warn(f"caching command_line = {command_line}")
        self.inputs.cache_object("command line", command_line)

    @ staticmethod
    def ignore_syscall(syscall: PtraceSyscall) -> bool:
        # A whitelist for file open etc would be easier, but first we need to
        # find those interesting functions...
        ignore = {
            "arch_prctl",
            "mprotect",
            "mmap",
            "munmap",
            "brk",
            "sbrk",
            "read",
            "pread64"}
        return syscall.name in ignore

    @ staticmethod
    def syscall_to_str(syscall: PtraceSyscall) -> str:
        return f"{syscall.format():80s} = {syscall.result_text}"

    def display_syscall(self, syscall: PtraceSyscall) -> None:
        log_debug(
            SyscallListener.syscall_to_str(syscall))

    def on_signal(self, event) -> None:
        # ProcessSignal has “signum” and “name” attributes
        # Note: ProcessSignal has a display() method to display its content.
        #       Use it just after receiving the message because it reads
        #       process memory to analyze the reasons why the signal was sent.
        log_debug(f"ToDo: handle signal {event}")

    def on_process_exited(self, event: ProcessExit) -> None:
        self.outputs.exit = event.exitcode
        print_event = True

        # process exited with an exitcode, killed by a signal or exited
        # abnormally. Note: ProcessExit has “exitcode” and “signum” attributes
        # (both can be None)
        state = event.process.syscall_state
        if (state.next_event == "exit") and state.syscall:

            # exit all threads in a process
            if state.syscall.name == "exit_group":
                print_event = False

        # Display exit message
        if print_event:
            log_debug(f"*** {event} ***")

    def on_new_process_event(self, event: NewProcessEvent) -> None:
        # new process created, e.g. after a fork() syscall
        # use process.parent attribute to get the parent process.
        process = event.process
        log_debug(
            "*** New process %s ***", process.pid)
        # TODO: where is prepareProcess gone?
        # self.prepareProcess(process)

    def on_process_execution(self, event) -> None:
        process = event.process
        log_debug(
            "*** Process %s execution ***",
            process.pid)

    def on_syscall(self, process: PtraceProcess):
        state = process.syscall_state
        syscall: PtraceSyscall = state.event(FunctionCallOptions(
            write_types=True,
            write_argname=True,
            string_max_length=200,
            replace_socketcall=False,
            write_address=True,
            max_array_count=50,
        ))
        if syscall and syscall.result is not None \
                and not SyscallListener.ignore_syscall(syscall):
            log_syscall = True

            if syscall.name == "openat":
                flags: int = syscall['flags'].value
                readonly: bool = flags in (O_READONLY, O_CLOEXEC)
                filename = Utils.read_filename_from_syscall_parameter(
                    syscall, 'filename')

                if readonly:
                    self.inputs.cache_file(filename)
                    log_syscall = False
                else:
                    logging.getLogger("gpcache").warning(
                        "> Abort: Not readonly access to %s", filename)

                openat_fd: int = syscall.result
                self.filedescriptors.open(
                    openat_fd, filename, self.syscall_to_str(syscall))

            if syscall.name == "access":
                filename = Utils.read_filename_from_syscall_parameter(
                    syscall, 'filename')
                mode = syscall['mode']
                result = syscall.result
                self.inputs.cache_access(filename, mode, result)
                log_syscall = False

            if syscall.name == "stat":
                filename = Utils.read_filename_from_syscall_parameter(
                    syscall, 'filename')

                # It's unfortunately to just cache the stat structure here.
                # It has different members (and therefore different size)
                # depending on a myriad of different things.
                # Therefore stats is called redundantly from Python.
                self.inputs.cache_stat(filename)
                log_syscall = False

            if syscall.name == "fstat":
                stat_fd: int = syscall['fd'].value
                self.inputs.cache_stat(
                    self.filedescriptors.get_filename(
                        stat_fd, self.syscall_to_str(syscall)))
                log_syscall = False

            if syscall.name == "close":
                close_fd: int = syscall['fd'].value
                self.filedescriptors.close(
                    close_fd, self.syscall_to_str(syscall))
                log_syscall = False

            if syscall.name in ("write"):
                write_fd: int = syscall['fd'].value
                self.filedescriptors.get_filename(
                    write_fd, self.syscall_to_str(syscall))

                buf: str = Utils.read_c_string(
                    syscall.process, syscall['buf'].value)
                if write_fd == 1:
                    self.outputs.write_stdout(buf)
                    log_syscall = False
                elif write_fd == 2:
                    self.outputs.write_stderr(buf)
                    log_syscall = False

            if log_syscall:
                self.display_syscall(syscall)


class MyDebuggerWrapper:
    """Main logic class?! Merge with SyscallListener?"""

    def __init__(self, verbose):
        self.verbose = verbose

        self.debugger = PtraceDebugger()
        self.debugger.traceFork()
        self.debugger.traceExec()
        self.debugger.traceClone()
        self.debugger.enableSysgood()

        self.syscall_listener = SyscallListener(verbose)

    def __del__(self):
        self.debugger.quit()

    def run(self, program):
        """Debug process and trigger syscall_listener on every syscall."""
        # Create stopped process (via fork followed by PTRACE_TRACEME) with
        # given parameters
        try:
            pid: int = ptrace.debugger.child.createChild(program,
                                                         no_stdout=False,
                                                         close_fds=False)

            process: PtraceProcess = self.debugger.addProcess(
                pid, is_attached=True)
        except (ProcessExit, PtraceError) as err:
            if isinstance(err, PtraceError) and err.errno == EPERM:
                error("ERROR: You are not allowed to trace child process!")
            else:
                error("ERROR: Process can no be attached!")
            return

        # Start process, but break at system calls
        process.syscall()

        # Turn exception based interface into one that uses on_* methods.
        # ToDo: what exactly does this condition test?
        while self.debugger:
            try:
                # We have set breakpoints to occure on syscalls.
                # Therefore breakpoint are handled by on_syscall.
                break_point = self.debugger.waitSyscall()
                self.syscall_listener.on_syscall(break_point.process)
                # proceed with unmodified syscall ?!
                break_point.process.syscall()
            except ProcessExit as interrupt:
                self.syscall_listener.on_process_exited(interrupt)
            except ProcessSignal as signal:
                self.syscall_listener.on_signal(signal)
                signal.process.syscall(signal.signum)
            except NewProcessEvent as event:
                self.syscall_listener.on_new_process_event(event)
                event.process.parent.syscall()
            except ProcessExecution as process_exec:
                self.syscall_listener.on_process_execution(process_exec)
                process_exec.process.syscall()


class GPCache():
    """
    This is basically the user interface class.

    It will probably also contain stuff like printing statistics and clearing
    cache.
    """

    def __init__(self, argv):
        self.args = argv

    @ staticmethod
    def run_and_collect(args):
        debugger = MyDebuggerWrapper(args.verbose)
        debugger.syscall_listener.set_command_line(args.program)

        try:
            debugger.run(args.program)
        except ProcessExit:  # as event:
            # FIXME: where is processExited?
            # processExited(event)
            pass
        except PtraceError as err:
            log_debug(f"ptrace() error: {err}")
        except KeyboardInterrupt:
            log_debug("Interrupted.")

        return (debugger.syscall_listener.inputs,
                debugger.syscall_listener.outputs)

    @ staticmethod
    def return_cached_or_run():
        pass

    def main(self):
        backend = FileBackend()
        outputs = backend.retrieve(self.args.program)

        if self.args.program:
            inputs, outputs = GPCache.run_and_collect(self.args)
            log_debug("\n\nEverything to cache:")
            inputs.print_summary()
            log_debug("\n\nCached output:")
            outputs.print_summary()

            location = backend.store(inputs, outputs)
            log_debug(
                f"cached data stored in {location}")


def create_parser():
    # short options taken over from ccache for familiarity
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "program", nargs='+',
        help="Full command line with parameters which this tool is"
             " supposed to cache")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print lots of logs to stdout (later to file)")
    parser.add_argument(
        "-s",
        "--stats",
        action="store_true",
        help="Print statistics on how much was cached (not yet implemented)")
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Run program and verify cache instead of using cached results"
             " (not yet implemented)")
    parser.add_argument(
        "-C",
        "--clear_cache",
        action="store_true",
        help="Remove everything from cache (not yet implemented)")
    parser.add_argument(
        "-z",
        "--clear_stats",
        action="store_true",
        help="Reset all statistics to 0 (not yet implemented)")
    parser.add_argument("--version", action="store_true",
                        help="Print version (not yet implemented)")
    return parser


if __name__ == "__main__":
    parsed_args = create_parser().parse_args()
    logging.basicConfig(
        format="[%(asctime)s.%(msecs)03d|%(levelname)s|%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=logging.DEBUG if parsed_args.verbose else logging.INFO)

    GPCache(parsed_args).main()
