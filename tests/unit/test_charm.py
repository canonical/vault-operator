# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import MagicMock, patch

import hcl  # type: ignore[import-untyped]
import ops
import ops.testing
from charm import VaultOperatorCharm, config_file_content_matches
from charms.operator_libs_linux.v2.snap import Snap, SnapState

PEER_RELATION_NAME = "vault-peers"


class MockNetwork:
    def __init__(self, bind_address: str):
        self.bind_address = bind_address


class MockBinding:
    def __init__(self, bind_address: str):
        self.network = MockNetwork(bind_address=bind_address)


class MockMachine:
    def __init__(self, exists_return_value: bool = False):
        self.exists_return_value = exists_return_value
        self.push_called = False

    def exists(self, path: str) -> bool:
        return self.exists_return_value

    def push(self, path: str, source: str) -> None:
        self.push_called = True
        self.push_called_with = {"path": path, "source": source}

    def pull(self, path: str) -> str:  # type: ignore[empty-body]
        pass

    def make_dir(self, path: str) -> None:
        pass

    def remove_path(self, path: str, recursive: bool = False) -> None:
        pass

    def send_signal(self, signal: int, service_name: str) -> None:
        pass


def read_file(path: str) -> str:
    """Read a file and returns as a string.

    Args:
        path (str): path to the file.

    Returns:
        str: content of the file.
    """
    with open(path, "r") as f:
        content = f.read()
    return content


class TestConfigFileContentMatches(unittest.TestCase):
    def test_given_identical_vault_config_when_config_file_content_matches_returns_true(self):
        existing_content = read_file("tests/unit/config.hcl")
        new_content = read_file("tests/unit/config.hcl")

        matches = config_file_content_matches(
            existing_content=existing_content, new_content=new_content
        )

        self.assertTrue(matches)

    def test_given_different_vault_config_when_config_file_content_matches_returns_false(self):
        existing_content = read_file("tests/unit/config.hcl")
        new_content = read_file("tests/unit/config_with_raft_peers.hcl")

        matches = config_file_content_matches(
            existing_content=existing_content, new_content=new_content
        )

        self.assertFalse(matches)

    def test_given_equivalent_vault_config_when_config_file_content_matches_returns_true(self):
        existing_content = read_file("tests/unit/config_with_raft_peers.hcl")
        new_content = read_file("tests/unit/config_with_raft_peers_equivalent.hcl")

        matches = config_file_content_matches(
            existing_content=existing_content, new_content=new_content
        )

        self.assertTrue(matches)


class TestCharm(unittest.TestCase):
    @patch("charm.Machine")
    def setUp(self, patch_machine):
        self.mock_machine = MockMachine()
        self.model_name = "whatever"
        patch_machine.return_value = self.mock_machine
        self.harness = ops.testing.Harness(VaultOperatorCharm)
        self.harness.set_model_name(self.model_name)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def _set_peer_relation(self) -> int:
        """Set the peer relation and return the relation id."""
        return self.harness.add_relation(
            relation_name=PEER_RELATION_NAME, remote_app=self.harness.charm.app.name
        )

    def _set_other_node_api_address_in_peer_relation(self, relation_id: int, unit_name: str):
        """Set the other node api address in the peer relation."""
        key_values = {"node_api_address": "http://5.2.1.9:8200"}
        self.harness.update_relation_data(
            app_or_unit=unit_name,
            relation_id=relation_id,
            key_values=key_values,
        )

    def _set_ca_certificate_secret_in_peer_relation(
        self, relation_id: int, private_key: str, certificate: str
    ) -> None:
        """Set the certificate secret in the peer relation."""
        content = {
            "certificate": certificate,
            "privatekey": private_key,
        }
        original_leader_state = self.harness.charm.unit.is_leader()
        with self.harness.hooks_disabled():
            self.harness.set_leader(is_leader=True)
            secret_id = self.harness.add_model_secret(
                owner=self.harness.charm.app.name, content=content
            )
            secret = self.harness.model.get_secret(id=secret_id)
            secret.set_info(label=CA_CERTIFICATE_JUJU_SECRET_LABEL)
            self.harness.set_leader(original_leader_state)
        key_values = {"vault-ca-certificates-secret-id": secret_id}
        self.harness.update_relation_data(
            app_or_unit=self.harness.charm.app.name,
            relation_id=relation_id,
            key_values=key_values,
        )

    @patch("charms.vault_k8s.v0.vault_tls.VaultTLSManager.configure_certificates", new=Mock())
    @patch("ops.model.Model.get_binding")
    @patch("charms.operator_libs_linux.v2.snap.SnapCache")
    def test_given_vault_snap_uninstalled_when_configure_then_vault_snap_installed(
        self, mock_snap_cache, patch_get_binding
    ):
        self.harness.set_leader(is_leader=True)
        vault_snap = MagicMock(spec=Snap, latest=False)
        snap_cache = {"vault": vault_snap}
        mock_snap_cache.return_value = snap_cache
        self._set_peer_relation()
        patch_get_binding.return_value = MockBinding(bind_address="1.2.1.2")

        self.harness.charm.on.install.emit()

        mock_snap_cache.assert_called_with()
        vault_snap.ensure.assert_called_with(
            SnapState.Latest, channel="1.15/beta", revision="2181"
        )
        vault_snap.hold.assert_called()

    @patch("charms.vault_k8s.v0.vault_tls.VaultTLSManager.configure_certificates", new=Mock())
    @patch("ops.model.Model.get_binding")
    @patch("charms.operator_libs_linux.v2.snap.SnapCache")
    def test_given_config_file_not_exists_when_configure_then_config_file_pushed(
        self, _, patch_get_binding
    ):
        self.harness.set_leader(is_leader=True)
        expected_content_hcl = hcl.loads(read_file("tests/unit/config.hcl"))
        patch_get_binding.return_value = MockBinding(bind_address="1.2.1.2")
        peer_relation_id = self._set_peer_relation()
        self._set_ca_certificate_secret_in_peer_relation(
            certificate="whatever certificate",
            private_key="whatever private key",
            relation_id=peer_relation_id,
        )

        self.harness.charm.on.install.emit()

        assert self.mock_machine.push_called
        assert self.mock_machine.push_called_with["path"] == "/var/snap/vault/common/vault.hcl"
        pushed_content_hcl = hcl.loads(self.mock_machine.push_called_with["source"])
        self.assertEqual(pushed_content_hcl, expected_content_hcl)

    @patch("ops.model.Model.get_binding")
    def test_given_bind_address_unavailable_when_configure_then_status_is_waiting(
        self, patch_get_binding
    ):
        patch_get_binding.return_value = None
        self.harness.set_leader(is_leader=False)
        self._set_peer_relation()

        self.harness.charm.on.install.emit()

        assert self.harness.charm.unit.status == ops.model.WaitingStatus(
            "Waiting for bind address"
        )

    @patch("ops.model.Model.get_binding")
    def test_given_unit_not_leader_and_peer_addresses_unavailable_when_configure_then_status_is_waiting(
        self, patch_get_binding
    ):
        patch_get_binding.return_value = MockBinding(bind_address="1.2.1.2")
        self.harness.set_leader(is_leader=False)
        self._set_peer_relation()

        self.harness.charm.on.install.emit()

        assert self.harness.charm.unit.status == ops.model.WaitingStatus(
            "Waiting for other units to provide their addresses"
        )

    @patch("charms.vault_k8s.v0.vault_tls.VaultTLSManager.configure_certificates", new=Mock())
    @patch("ops.model.Model.get_binding")
    @patch("charms.operator_libs_linux.v2.snap.SnapCache")
    def test_given_when_configure_then_service_started(self, mock_snap_cache, patch_get_binding):
        patch_get_binding.return_value = MockBinding(bind_address="1.2.1.2")
        vault_snap = MagicMock(spec=Snap)
        snap_cache = {"vault": vault_snap}
        mock_snap_cache.return_value = snap_cache
        self.harness.set_leader(is_leader=False)
        peer_relation_id = self._set_peer_relation()
        other_unit_name = f"{self.harness.charm.app.name}/1"
        self.harness.add_relation_unit(
            relation_id=peer_relation_id, remote_unit_name=other_unit_name
        )

        self._set_other_node_api_address_in_peer_relation(
            relation_id=peer_relation_id, unit_name=other_unit_name
        )
        self._set_ca_certificate_secret_in_peer_relation(
            certificate="whatever certificate",
            private_key="whatever private key",
            relation_id=peer_relation_id,
        )

        self.harness.charm.on.install.emit()

        mock_snap_cache.assert_called_with()
        vault_snap.start.assert_called_with(services=["vaultd"])

    @patch("charms.vault_k8s.v0.vault_tls.VaultTLSManager.configure_certificates", new=Mock())
    @patch("ops.model.Model.get_binding")
    @patch("charms.operator_libs_linux.v2.snap.SnapCache")
    def test_given_unit_not_leader_and_peer_addresses_available_when_configure_then_status_is_active(
        self, _, patch_get_binding
    ):
        patch_get_binding.return_value = MockBinding(bind_address="1.2.1.2")
        self.harness.set_leader(is_leader=False)
        peer_relation_id = peer_relation_id = self._set_peer_relation()
        other_unit_name = f"{self.harness.charm.app.name}/1"
        self.harness.add_relation_unit(
            relation_id=peer_relation_id, remote_unit_name=other_unit_name
        )
        self._set_ca_certificate_secret_in_peer_relation(
            certificate="whatever certificate",
            private_key="whatever private key",
            relation_id=peer_relation_id,
        )

        self._set_other_node_api_address_in_peer_relation(
            relation_id=peer_relation_id, unit_name=other_unit_name
        )

        self.harness.charm.on.install.emit()

        self.assertEqual(
            self.harness.charm.unit.status,
            ActiveStatus(),
        )
