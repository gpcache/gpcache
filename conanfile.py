from conans import ConanFile, CMake, tools


class gpcache(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    requires = (
        "fmt/8.1.1",
        "abseil/20211102.0",
        "libb2/20190723",
        "spdlog/1.9.2",
        "nlohmann_json/3.10.5",
        "pfr/2.0.2")
    generators = "cmake"  # cmake_paths

    def build_requirements(self):
        self.build_requires("catch2/2.13.8")
        if self.settings.compiler == "gcc":
            self.build_requires("elfutils/0.180")

    def configure(self):
        # This is just terrible.
        # Doesn't seem there is a better way to do this in Conan.
        if self.settings.compiler.cppstd != 20:
            raise Exception(
                "Dependencies need to be compiled in C++20 ABI, "
                "please call install with: "
                "`conan install .. --settings compiler.cppstd=20 "
                "--build=missing`")

        # redundand check?!
        tools.check_min_cppstd(self, "20")

    def source(self):
        self.run("git clone https://github.com/gpcache/gpcache.git")

    def imports(self):
        pass

    def build(self):
        cmake = CMake(self)  # generator="Ninja", build_type="Debug"
        cmake.definitions["FORCE_COLORED_OUTPUT"] = "ON"
        cmake.configure()
        cmake.build()
