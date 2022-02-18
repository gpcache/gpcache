#pragma once

#include "main/state.h"

#include "wrappers/filesystem.h"
#include "wrappers/json.h"
#include "wrappers/ptrace.h"
#include "wrappers/ptrace/SyscallWrappers.h"

#include <spdlog/spdlog.h>

namespace gpcache
{
struct CachedSyscall_Mmap
{
    static constexpr char name[] = "mmap";

    struct Parameters
    {
        bool is_addr_nullptr;
        size_t length;
        int prot;
        int flags;
        int fd;
        off_t offset;

        BOILERPLATE(Parameters, is_addr_nullptr, length, prot, flags, fd, offset)
    } parameters;

    struct Result
    {
        bool is_addr_nullptr;
        int errno_code;
        std::string file_hash;

        BOILERPLATE(Result, is_addr_nullptr, errno_code, file_hash)
    } result;

    BOILERPLATE(CachedSyscall_Mmap, parameters, result)
};

auto execute_cached_syscall(State &, CachedSyscall_Mmap::Parameters const &) -> CachedSyscall_Mmap::Result;
auto covert_real_to_cachable_syscall(State &, Syscall_mmap const &) -> std::variant<bool, CachedSyscall_Mmap>;
} // namespace gpcache
