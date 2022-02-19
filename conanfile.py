from conans import ConanFile, CMake, tools


class gpcache(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    requires = (
        "fmt/8.0.1",  # this exact version is required by spdlog/1.9.2
        "abseil/20211102.0",
        "libb2/20190723",
        "spdlog/1.9.2",
        "nlohmann_json/3.10.5",
        "pfr/2.0.2")
    generators = "cmake"  # cmake_paths

    def build_requirements(self):
        print(f"build_requirements(self)")
        self.settings.compiler.cppstd = 20
        self.build_requires("cmake/3.22.0")
        self.build_requires("catch2/2.13.8")
        if self.settings.compiler == "gcc":
            self.build_requires("elfutils/0.180")

    def validate(self):
        print(f"validate(self)")
        tools.check_min_cppstd(self, "20")

    def configure(self):
        print(f"configure(self)")
        if not tools.valid_min_cppstd(self, "20"):
            self.output.error("C++20 is required")

    def source(self):
        self.run("git clone https://github.com/gpcache/gpcache.git")

    def imports(self):
        print(f"imports(self)")
        pass

    def build(self):
        print(f"build(self)")
        cmake = CMake(self)  # generator="Ninja", build_type="Debug"
        cmake.definitions["FORCE_COLORED_OUTPUT"] = "ON"
        cmake.configure()
        cmake.build()
