[![Open in Visual Studio Code](https://open.vscode.dev/badges/open-in-vscode.svg)](https://open.vscode.dev/gpcache/gpcache)

# gpcache
General Purpose Cache will speed up repetitios testing, just as ccache speeds up repetitios compilations.

## How gpcache helps
- gpcache will execute your test in a debugger-like mode.
- It will track all additional dependencies like shared libraries, config files, databases etc.
- It will cache all dependencies and the test result
- In case the same executable is run again and all dependencies are unmodified it will quickly print the test result without rerunning your executable

## When gpcache helps
If you have a testsuite of badly written unittest-like executables and an average commit changes only a small part of them.

Details:
* Local compilation usually is usually done incrementally and your build system takes care to not touch executables which do not need recompilation.
  However test drivers (e.g. CTest, bash scripts, etc) are usually not that smart and run your entire test suite.
  This is where this tool shines (will shine). It will report cached test results without actually rerunning your slow unittests.
* CI compilation is only helped if you compile incrementally or compile reproducible binaries.

Preconditions:
* Tests must be slow but stable (automatic flaky test detection is possible in the future)
* Tests must not rely on untrackable features like message queues, sockets, etc

---

# Current state of gpcache
1. Proof of concept in python :heavy_check_mark:
2. Proof of concept in C++ :heavy_check_mark:
3. Prototype (in C++) <-- current focus
4. Production usable 1.0 with small feature set


---
# Installation
gpcache does not really have any usable mode at the moment.
The goal will be to use it like ccache.

Supported OS:
* Tested on Ubuntu 18
* Tested on Ubuntu 20
* Windows will not be supported (at least until 3.0)


---
# Build gpcache from source

## Prerequisites:
- C++: g++10 or clang-10
- System: tested on Ubuntu 18 and Ubuntu 20
- Conan: `pip3 install conan`

For more (and guaranteed to work) details have a look at [CI](.github/workflows/build.yaml)

### Why Conan?
C++ lacks a package manager. Currently/finally some have appeared.
It's not clear yet (to me) which one is the best.
However as I do need to get started and not using a package manager is not an option, let's use conan for now.


## Getting and compiling gpcache
```
git clone https://github.com/gpcache/gpcache.git
mkdir gpcache_build
cd gpcache_build
conan install ../gpcache --settings compiler.cppstd=20 --build=missing

# You'll need to run the first build via conan, afterwards you can use make/ninja.
conan build ../gpcache
```

### Other options
Building with clang++:
```
conan install ../gpcache -s compiler=clang -s compiler.version=10 -s compiler.cppstd=20 --build=missing -e CXX=clang++
```

Debugging g++:
```
conan install ../gpcache -s compiler=gcc -s compiler.version=10 -s compiler.cppstd=20 --build=missing -e CC=gcc-10 -e CXX=g++-10 -e FORCE_COLORED_OUTPUT=ON -s build_type=Debug
```

Debugging clang:
```
conan install ../gpcache -s compiler=clang -s compiler.version=10 -s compiler.cppstd=20 --build=missing -e CXX=clang++ -e FORCE_COLORED_OUTPUT=ON -s build_type=Debug
```
