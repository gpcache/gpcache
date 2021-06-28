#!/usr/bin/env python3
from gpcache import Utils, Inputs, Outputs

import logging
import os
import os.path
import yaml
from typing import Optional

info = logging.getLogger("gpcache").info
warn = logging.getLogger("gpcache").warning
log_debug = logging.getLogger("gpcache").debug


class FileBackend:
    """
    Stores cache in local files

    Uses directories to represent tree of all possible inputs.
    Maybe not the best idea. Works for now.
    """

    # ToDo: XDG / configurable
    CACHE_DIR: str = ".cache_dir"

    @staticmethod
    def _yaml_from_file(filepath) -> typing.Any:
        if not os.path.exists(filepath):
            return None
        with open(filepath, "r") as yamlfile:
            return yaml.safe_load(yamlfile)

    # max path length is limited in linux
    @staticmethod
    def _make_safe_short_filename(unsafe_name, target_length=20) -> str:
        unsafe_name = str(unsafe_name)
        if len(unsafe_name) > target_length:
            # no idea what a good number is
            digest_size = int(len(unsafe_name) / 10)
            if digest_size > target_length - 5:
                digest_size = target_length - 5

            unsafe_name = unsafe_name[:(target_length - digest_size)] + \
                Utils.calculate_hash_of_str(unsafe_name, digest_size)
        return Utils.make_safe_filename(unsafe_name)

    @classmethod
    def _ensure_yaml_content(cls, yamlfile, content) -> None:
        """ In case the directory is not sufficiently unique, the exact
        command is stored in yaml file """
        filecontent = cls._yaml_from_file(yamlfile)
        if not filecontent:
            os.makedirs(os.path.dirname(yamlfile), 0o777, True)
            with open(yamlfile, "w") as yamlfile_writer:
                yaml.safe_dump(content, yamlfile_writer)
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

            path += "/" + self._make_safe_short_filename(actionStr)
            self._ensure_yaml_content(f"{path}/action.yaml", actionStr)
            path += "/" + self._make_safe_short_filename(resultStr)
            self._ensure_yaml_content(f"{path}/result.yaml", resultStr)

        os.makedirs(path, 0o777, True)

        with open(f"{path}/outputs.yaml", "w") as outputs_yaml:
            yaml.safe_dump(outputs.files_to_write, outputs_yaml)
            yaml.safe_dump(outputs.stdout, outputs_yaml)
            yaml.safe_dump(outputs.stderr, outputs_yaml)

        return path

    def retrieve(self, command_line) -> Optional[Outputs]:
        path = f"{self.CACHE_DIR}/command line/{self._make_safe_short_filename(str(command_line))}"
        cached = self._yaml_from_file(f"{path}/result.yaml")
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
            cached = self._yaml_from_file(f".{path}/action.yaml")
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
