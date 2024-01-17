# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import patch

import ops
import ops.testing
from charm import VaultOperatorCharm
from charms.operator_libs_linux.v1.snap import SnapState


class MockSnapObject:
    def __init__(self, name):
        self.name = name
        self.ensure_called = False
        self.ensure_called_with = None
        self.hold_called = False

    def ensure(self, state, channel, revision):
        self.ensure_called = True
        self.ensure_called_with = (state, channel, revision)

    def hold(self):
        self.hold_called = True


class MockNetwork:
    def __init__(self, bind_address: str, ingress_address: str):
        self.bind_address = bind_address
        self.ingress_address = ingress_address


class MockBinding:
    def __init__(self, bind_address: str, ingress_address: str):
        self.network = MockNetwork(bind_address=bind_address, ingress_address=ingress_address)


class MockUnitFileDirectory:
    def exists(self, path: str) -> bool:
        pass

    def push(self, path: str, source: str) -> None:
        pass

    def pull(self, path: str) -> str:
        pass


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.app_name = "vault-k8s"
        self.harness = ops.testing.Harness(VaultOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def _set_peer_relation(self) -> int:
        """Set the peer relation and return the relation id."""
        return self.harness.add_relation(relation_name="vault-peers", remote_app=self.app_name)

    @patch("charm.UnitFileDirectory")
    @patch("ops.model.Model.get_binding")
    @patch("charms.operator_libs_linux.v1.snap.SnapCache")
    def test_given_vault_snap_uninstalled_when_configure_then_vault_snap_installed(
        self, mock_snap_cache, patch_get_binding, patch_unit_file_directory
    ):
        vault_snap = MockSnapObject("vault")
        snap_cache = {"vault": vault_snap}
        mock_snap_cache.return_value = snap_cache
        self._set_peer_relation()
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2", ingress_address="10.1.0.1"
        )
        patch_unit_file_directory.return_value = MockUnitFileDirectory()

        self.harness.charm.on.install.emit()

        mock_snap_cache.assert_called_once_with()

        assert vault_snap.ensure_called
        assert vault_snap.ensure_called_with == (SnapState.Latest, "1.12/stable", 2166)
        assert vault_snap.hold_called
