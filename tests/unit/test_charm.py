# Copyright 2023 Canonical Ltd.
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


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = ops.testing.Harness(VaultOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    @patch("charms.operator_libs_linux.v1.snap.SnapCache")
    def test_given_vault_snap_uninstalled_when_configure_then_vault_snap_installed(
        self, mock_snap_cache
    ):
        vault_snap = MockSnapObject("vault")
        snap_cache = {"vault": vault_snap}
        mock_snap_cache.return_value = snap_cache

        self.harness.charm.on.install.emit()

        mock_snap_cache.assert_called_once_with()

        assert vault_snap.ensure_called
        assert vault_snap.ensure_called_with == (SnapState.Latest, "1.12/stable", 2166)
        assert vault_snap.hold_called
