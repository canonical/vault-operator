#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Machine abstraction for the Vault charm."""


import logging
import os
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)


class Machine:
    """A class to interact with a unit machine.

    This class has the same method signatures as Pebble API in the Ops
    Library. This is to improve consistency between the Machine and Kubernetes
    versions of the charm.
    """

    def exists(self, path: str) -> bool:
        """Check if a file exists.

        Args:
            path: The path of the file

        Returns:
            bool: Whether the file exists
        """
        return os.path.isfile(path)

    def pull(self, path: str) -> str:
        """Get the content of a file.

        Args:
            path: The path of the file

        Returns:
            str: The content of the file
        """
        with open(path, "r") as read_file:
            return read_file.read()

    def push(self, path: str, source: str) -> None:
        """Pushes a file to the unit.

        Args:
            path: The path of the file
            source: The contents of the file to be pushed
        """
        with open(path, "w") as write_file:
            write_file.write(source)
            logger.info("Pushed file %s", path)

    def make_dir(self, path: str) -> None:
        """Create a directory."""
        Path(path).mkdir(parents=True, exist_ok=True)

    def remove_path(self, path: str, recursive: bool = False) -> None:
        """Remove a file or directory.

        Args:
            path: The path of the file or directory
            recursive: Whether to remove recursively
        raises:
            ValueError: If the path is not absolute.
        """
        if not os.path.isabs(path):
            raise ValueError(f"The provided path is not absolute: {path}")
        if os.path.isdir(path) and recursive:
            shutil.rmtree(path)
            logger.info("Recursively removed directory %s", path)
        elif os.path.isfile(path) or (os.path.isdir(path) and not recursive):
            os.remove(path)
            logger.info("Removed file or directory %s", path)
        else:
            logger.info("No such file or directory: %s", path)
