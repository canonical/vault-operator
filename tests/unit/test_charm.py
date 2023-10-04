# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest

import ops
import ops.testing
from charm import VaultOperatorCharm


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = ops.testing.Harness(VaultOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def test_given_when_then(self):
        pass
