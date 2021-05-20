# gpcache
General Purpose Cache will speed up repetitios retesting, just as ccache speeds up repetitions recompilations.

## How gpcache helps
- gpcache will execute your test in a debugger-like mode.
- It will track all additional dependencies like shared libraries, config files, databases etc.
- It will cache all dependencies and the test result
- In case the same executable is run again and all dependencies are unmodified it will quickly print the test result without rerunning your executable

## When this helps
If you have a testsuite of badly written unittest-like executables and an average commit changes only a small part of them.

Details:
* Local compilation usually is usually done incrementally and your build system takes care to not touch executables which do not need recompilation.
  However test drivers (e.g. CTest, bash scripts, etc) are usually not that smart and run your entire test suite.
  This is where this tool shines (will shine). It will report cached test results without actually rerunning your slow unittests.
* CI compilation is only helped if you compile incrementally or compile reproducible binaries.

Preconditions:
* Tests must be slow but stable (automatic flaky test detection is possible in the future)
* Tests must not rely on untrackable features like message queues, sockets, etc


## Current state
- Proof of concept written in python, but actual tool shall be written in C++
- C++ implementation has passed the proof of concept (as expected), but has not yet catched up with the python version

### Why C++
Main trigger was stats. I was not able to figure out how to use stats result in python and had to issue a manual stats. Therefore a new syscall. Besides performance problems this results in asynchronities since sometimes differnt values will be cached than actually used by the to-be-cached-tool.

## Build gpcache from source
Demonstrating with an in source build, although that is not really encouraged.
Not sure I'm using conan correctly here, but hey... "it works on my machine".

#### Prerequisites:
Conan
`pip3 install conan`

Why Conan?
C++ lacks a package manager. Currently/finally some have appeared.
It's not clear yet (to me) which one is the best.
However as I do need to get started and not using a package manager is not an option, let's use conan for now.

#### Getting and compiling gpcache
```
git clone https://github.com/gpcache/gpcache.git
mkdir gpcache_build
cd gpcache_build
conan install ../gpcache --settings compiler.cppstd=20 --build=missing

You'll need to run the first build via conan, afterwards you can use make/ninja.
conan build ../gpcache
```

Changing compiler:
`conan install ../gpcache -s compiler=clang -s compiler.version=10 -s compiler.cppstd=20 --build=missing -e CXX=clang++`

Debugging:
`conan install ../gpcache -s compiler=clang -s compiler.version=10 -s compiler.cppstd=20 --build=missing -e CXX=clang++ -e FORCE_COLORED_OUTPUT=ON -s build_type=Debug`
