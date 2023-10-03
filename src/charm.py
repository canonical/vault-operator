#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.


"""A machine charm for Vault."""

import logging

from ops.charm import CharmBase, InstallEvent
from ops.main import main
from ops.model import ActiveStatus

logger = logging.getLogger(__name__)


class VaultOperatorCharm(CharmBase):
    """Charm the service."""

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.install, self._on_install)

    def _on_install(self, event: InstallEvent):
        """Handle installation."""
        self.unit.status = ActiveStatus()


if __name__ == "__main__":  # pragma: nocover
    main(VaultOperatorCharm)
