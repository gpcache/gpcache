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


## Build gpcache from source
Demonstrating with an in source build, although that is not really encouraged.
Not sure I'm using conan correctly here, but hey... "it works on my machine".

#### Prerequisites:
Conan
`pip3 install conan`

#### Getting and compiling gpcache
```
git clone https://github.com/gpcache/gpcache.git
cd gpcache
mkdir build
conan install .. # installs all dependencies like fmt
conan build ..
```
