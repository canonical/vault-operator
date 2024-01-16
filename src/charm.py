#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.


"""A machine charm for Vault."""

import logging

from charms.operator_libs_linux.v1 import snap
from ops.charm import CharmBase, InstallEvent
from ops.main import main
from ops.model import ActiveStatus, MaintenanceStatus

logger = logging.getLogger(__name__)

VAULT_SNAP_NAME = "vault"
VAULT_SNAP_CHANNEL = "1.10/stable"
VAULT_SNAP_REVISION = 2091


class VaultOperatorCharm(CharmBase):
    """Charm the service."""

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.install, self._configure)
        self.framework.observe(self.on.update_status, self._configure)

    def _configure(self, event: InstallEvent):
        """Handle Vault installation."""
        self.unit.status = MaintenanceStatus("Installing Vault")
        self._install_vault_snap()
        self.unit.status = ActiveStatus()

    def _install_vault_snap(self) -> None:
        """Installs the Vault snap in the machine."""
        try:
            snap_cache = snap.SnapCache()
            vault_snap = snap_cache[VAULT_SNAP_NAME]
            vault_snap.ensure(
                snap.SnapState.Latest, channel=VAULT_SNAP_CHANNEL, revision=VAULT_SNAP_REVISION
            )
            vault_snap.hold()

        except snap.SnapError as e:
            logger.error("An exception occurred when installing Vault. Reason: %s", str(e))
            raise


if __name__ == "__main__":  # pragma: nocover
    main(VaultOperatorCharm)
