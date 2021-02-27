from conans import ConanFile, CMake, tools


class gpcache(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    requires = "fmt/7.1.3", "abseil/20200923.3"
    build_requires = "catch2/2.13.4"
    generators = "cmake"  # cmake_paths

    def configure(self):
        # This is just terrible.
        # Doesn't seem there is a better way to do this in Conan.
        if self.settings.compiler.cppstd != 20:
            raise "Sorry, you have to call install with: conan install .. --settings compiler.cppstd=20 --build=missing"
        tools.check_min_cppstd(self, "20")
        pass

    def source(self):
        self.run("git clone https://github.com/gpcache/gpcache.git")

    def imports(self):
        self.copy("*.dll", dst="bin", src="bin")  # From bin to bin
        self.copy("*.dylib*", dst="bin", src="lib")  # From lib to bin

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()
