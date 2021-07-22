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
Proof of concept written in python (see history) and C++.
C++ looks more promising, but is not a clear winner so far.
Both languages have advantages... and more importantly huge disadvantages.

Pro Python (see history):
* The amount of code required compared to C++ is so much smaller, it's astonishing (I'm a C++ programmer).

### Pro C++
* Main trigger was stats. I was not able to figure out how to use stats result in python and had to issue a second stats call from python.
  Besides performance problems this results in asynchronities since sometimes differnt values will be cached than actually used by the to-be-cached-tool.
* Works on any machine (e.g. actual target hardware)

---
# Installation

## C++: Build gpcache from source
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

# You'll need to run the first build via conan, afterwards you can use make/ninja.
conan build ../gpcache
```

#### Other options
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


## Python: Build gpcache from source
Ensure python3 is available.
