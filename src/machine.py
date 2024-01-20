#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Machine abstraction for the Vault charm."""


import logging
import os

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
