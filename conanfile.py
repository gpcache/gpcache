from conans import ConanFile, CMake, tools


class gpcache(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    requires = "fmt/7.1.3", "abseil/20200923.3", "libb2/20190723", "spdlog/1.8.5"
    build_requires = "cmake/3.20.0", "ninja/1.10.2", "catch2/2.13.4"
    generators = "cmake"  # cmake_paths

    def configure(self):
        # This is just terrible.
        # Doesn't seem there is a better way to do this in Conan.
        if self.settings.compiler.cppstd != 20:
            raise Exception(
                "Dependencies need to be compiled in C++20 ABI, please call install with: conan install .. --settings compiler.cppstd=20 --build=missing")

        # redundand check?!
        tools.check_min_cppstd(self, "20")

    def source(self):
        self.run("git clone https://github.com/gpcache/gpcache.git")

    def imports(self):
        self.copy("*.dll", dst="bin", src="bin")  # From bin to bin
        self.copy("*.dylib*", dst="bin", src="lib")  # From lib to bin

    def build(self):
        cmake = CMake(self, "Ninja")
        cmake.definitions["FORCE_COLORED_OUTPUT"] = "ON"
        cmake.configure()
        cmake.build()
