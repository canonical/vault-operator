# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import MagicMock, Mock, call, patch

import hcl
import ops
import ops.testing
from charm import (
    MACHINE_TLS_FILE_DIRECTORY_PATH,
    VAULT_CHARM_APPROLE_SECRET_LABEL,
    VAULT_CHARM_POLICY_NAME,
    VAULT_CHARM_POLICY_PATH,
    VAULT_DEFAULT_POLICY_NAME,
    VAULT_PKI_CSR_SECRET_LABEL,
    VaultOperatorCharm,
    config_file_content_matches,
)
from charms.operator_libs_linux.v2.snap import Snap, SnapState
from charms.tls_certificates_interface.v3.tls_certificates import (
    CertificateAvailableEvent,
    ProviderCertificate,
)
from charms.vault_k8s.v0.vault_client import AuditDeviceType, SecretsBackend, Token, Vault
from charms.vault_k8s.v0.vault_tls import CA_CERTIFICATE_JUJU_SECRET_LABEL

PEER_RELATION_NAME = "vault-peers"
VAULT_STORAGE_PATH = "/var/snap/vault/common/raft"
TLS_CERTIFICATES_LIB_PATH = "charms.tls_certificates_interface.v3.tls_certificates"
TLS_CERTIFICATES_PKI_RELATION_NAME = "tls-certificates-pki"

class MockNetwork:
    def __init__(self, bind_address: str):
        self.bind_address = bind_address


class MockBinding:
    def __init__(self, bind_address: str):
        self.network = MockNetwork(bind_address=bind_address)


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
    patcher_snap_cache = patch("charm.snap.SnapCache")
    patcher_vault_tls_manager = patch("charm.VaultTLSManager")
    patcher_machine = patch("charm.Machine")
    patcher_vault = patch("charm.Vault")

    def setUp(self):
        self.mock_snap_cache = TestCharm.patcher_snap_cache.start()
        self.mock_vault_tls_manager = TestCharm.patcher_vault_tls_manager.start().return_value
        self.mock_machine = TestCharm.patcher_machine.start().return_value
        self.mock_vault = TestCharm.patcher_vault.start().return_value

        self.app_name = "vault"
        self.model_name = "whatever"
        self.harness = ops.testing.Harness(VaultOperatorCharm)
        self.harness.set_model_name(self.model_name)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def tearDown(self) -> None:
        TestCharm.patcher_snap_cache.stop()
        TestCharm.patcher_vault_tls_manager.stop()
        TestCharm.patcher_machine.stop()

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

    def _set_ca_certificate_secret(self, private_key: str, certificate: str) -> None:
        """Set the certificate secret."""
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

    def _set_csr_secret_in_peer_relation(self, relation_id: int, csr: str) -> None:
        """Set the csr secret in the peer relation."""
        content = {
            "csr": csr,
        }
        original_leader_state = self.harness.charm.unit.is_leader()
        with self.harness.hooks_disabled():
            self.harness.set_leader(is_leader=True)
            secret_id = self.harness.add_model_secret(owner=self.app_name, content=content)
            secret = self.harness.model.get_secret(id=secret_id)
            secret.set_info(label=VAULT_PKI_CSR_SECRET_LABEL)
            self.harness.set_leader(original_leader_state)
        key_values = {"vault-pki-csr-secret-id": secret_id}
        self.harness.update_relation_data(
            app_or_unit=self.app_name,
            relation_id=relation_id,
            key_values=key_values,
        )

    @patch("charm.config_file_content_matches", new=Mock())
    @patch("ops.model.Model.get_binding")
    def test_given_vault_snap_uninstalled_when_configure_then_vault_snap_installed(
        self, patch_get_binding: MagicMock
    ):
        self.harness.set_leader(is_leader=True)
        vault_snap = MagicMock(spec=Snap, latest=False)
        snap_cache = {"vault": vault_snap}
        self.mock_snap_cache.return_value = snap_cache
        self._set_peer_relation()
        patch_get_binding.return_value = MockBinding(bind_address="1.2.1.2")

        self.harness.charm.on.install.emit()

        self.mock_snap_cache.assert_called_with()
        vault_snap.ensure.assert_called_with(
            SnapState.Latest, channel="1.15/beta", revision="2181"
        )
        vault_snap.hold.assert_called()

    @patch("charm.config_file_content_matches", new=Mock(return_value=False))
    @patch("ops.model.Model.get_binding")
    def test_given_config_file_not_exists_when_configure_then_config_file_pushed(
        self, patch_get_binding
    ):
        self.harness.set_leader(is_leader=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        expected_content_hcl = hcl.loads(read_file("tests/unit/config.hcl"))
        patch_get_binding.return_value = MockBinding(bind_address="1.2.1.2")
        self._set_peer_relation()
        self._set_ca_certificate_secret(
            certificate="whatever certificate",
            private_key="whatever private key",
        )

        self.harness.charm.on.install.emit()

        self.mock_machine.push.assert_called()
        _, kwargs = self.mock_machine.push.call_args
        assert kwargs["path"] == "/var/snap/vault/common/vault.hcl"
        pushed_content_hcl = hcl.loads(kwargs["source"])
        self.assertEqual(pushed_content_hcl, expected_content_hcl)

    @patch("ops.model.Model.get_binding")
    def test_given_bind_address_unavailable_when_collectstatus_then_status_is_waiting(
        self, patch_get_binding
    ):
        patch_get_binding.return_value = None
        self.harness.set_leader(is_leader=False)
        self._set_peer_relation()

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.charm.unit.status,
            ops.WaitingStatus("Waiting for bind address"),
        )

    @patch("ops.model.Model.get_binding")
    def test_given_unit_not_leader_and_peer_addresses_unavailable_when_collectstatus_then_status_is_waiting(
        self, patch_get_binding
    ):
        patch_get_binding.return_value = MockBinding(bind_address="1.2.1.2")
        self.mock_vault_tls_manager.tls_file_available_in_charm.return_value = False
        self.harness.set_leader(is_leader=False)
        self._set_peer_relation()

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.charm.unit.status,
            ops.WaitingStatus("Waiting for other units to provide their addresses"),
        )

    @patch("ops.model.Model.get_binding")
    def test_given_unit_is_leader_and_ca_certificate_saved_when_collectstatus_then_status_is_blocked(
        self,
        patch_get_binding,
    ):
        self.mock_machine.exists.return_value = False
        patch_get_binding.return_value = MockBinding(bind_address="1.2.1.2")
        self.harness.set_leader(is_leader=False)
        peer_relation_id = self._set_peer_relation()
        other_unit_name = f"{self.harness.charm.app.name}/1"
        self.harness.add_relation_unit(
            relation_id=peer_relation_id, remote_unit_name=other_unit_name
        )
        self._set_other_node_api_address_in_peer_relation(
            relation_id=peer_relation_id, unit_name=other_unit_name
        )
        self.mock_vault_tls_manager.tls_file_pushed_to_workload.return_value = True

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.charm.unit.status,
            ops.BlockedStatus("Waiting for Vault to be unsealed"),
        )

    @patch("charm.config_file_content_matches", new=Mock())
    @patch("ops.model.Model.get_binding")
    def test_given_vault_snap_installed_when_configure_then_directories_created(
        self,
        patch_get_binding,
    ):
        patch_get_binding.return_value = MockBinding(bind_address="1.2.1.2")
        vault_snap = MagicMock(spec=Snap)
        snap_cache = {"vault": vault_snap}
        self.mock_snap_cache.return_value = snap_cache
        self.harness.set_leader(is_leader=False)
        peer_relation_id = self._set_peer_relation()
        other_unit_name = f"{self.harness.charm.app.name}/1"
        self.harness.add_relation_unit(
            relation_id=peer_relation_id, remote_unit_name=other_unit_name
        )
        self._set_ca_certificate_secret(
            certificate="whatever certificate",
            private_key="whatever private key",
        )
        self._set_other_node_api_address_in_peer_relation(
            relation_id=peer_relation_id, unit_name=other_unit_name
        )

        self.harness.charm.on.install.emit()

        self.mock_machine.make_dir.assert_called()
        assert call(path=VAULT_STORAGE_PATH) in self.mock_machine.make_dir.call_args_list
        assert (
            call(path=MACHINE_TLS_FILE_DIRECTORY_PATH) in self.mock_machine.make_dir.call_args_list
        )

    @patch("charm.config_file_content_matches", new=Mock())
    @patch("ops.model.Model.get_binding")
    def test_given_vault_snap_installed_when_configure_then_certificates_are_configured(
        self,
        patch_get_binding,
    ):
        bind_address = "1.2.1.2"
        patch_get_binding.return_value = MockBinding(bind_address=bind_address)
        vault_snap = MagicMock(spec=Snap)
        snap_cache = {"vault": vault_snap}
        self.mock_snap_cache.return_value = snap_cache
        self.harness.set_leader(is_leader=False)
        peer_relation_id = self._set_peer_relation()
        other_unit_name = f"{self.harness.charm.app.name}/1"
        self.harness.add_relation_unit(
            relation_id=peer_relation_id, remote_unit_name=other_unit_name
        )
        self._set_ca_certificate_secret(
            certificate="whatever certificate",
            private_key="whatever private key",
        )
        self._set_other_node_api_address_in_peer_relation(
            relation_id=peer_relation_id, unit_name=other_unit_name
        )

        self.harness.charm.on.install.emit()

        self.mock_vault_tls_manager.configure_certificates.assert_called_with(bind_address)

    @patch("charm.config_file_content_matches", new=Mock())
    @patch("ops.model.Model.get_binding")
    def test_given_snap_installed_when_configure_then_service_started(
        self,
        patch_get_binding,
    ):
        patch_get_binding.return_value = MockBinding(bind_address="1.2.1.2")
        vault_snap = MagicMock(spec=Snap)
        snap_cache = {"vault": vault_snap}
        self.mock_snap_cache.return_value = snap_cache
        self.harness.set_leader(is_leader=False)
        peer_relation_id = self._set_peer_relation()
        other_unit_name = f"{self.harness.charm.app.name}/1"
        self.harness.add_relation_unit(
            relation_id=peer_relation_id, remote_unit_name=other_unit_name
        )

        self._set_other_node_api_address_in_peer_relation(
            relation_id=peer_relation_id, unit_name=other_unit_name
        )
        self._set_ca_certificate_secret(
            certificate="whatever certificate",
            private_key="whatever private key",
        )

        self.harness.charm.on.install.emit()

        self.mock_snap_cache.assert_called_with()
        vault_snap.start.assert_called_with(services=["vaultd"])

    @patch("charm.config_file_content_matches", new=Mock())
    @patch("ops.model.Model.get_binding")
    def test_given_unit_not_leader_and_peer_addresses_available_and_vault_unsealed_when_collectstatus_then_status_is_active(
        self,
        patch_get_binding,
    ):
        self.mock_vault.configure_mock(**{"is_sealed.return_value": False})

        patch_get_binding.return_value = MockBinding(bind_address="1.2.1.2")
        self.harness.set_leader(is_leader=False)
        self.harness.charm.app.add_secret(
            {"role-id": "role-id", "secret-id": "secret-id"},
            label=VAULT_CHARM_APPROLE_SECRET_LABEL,
        )
        peer_relation_id = self._set_peer_relation()
        other_unit_name = f"{self.harness.charm.app.name}/1"
        self.harness.add_relation_unit(
            relation_id=peer_relation_id, remote_unit_name=other_unit_name
        )
        self._set_ca_certificate_secret(
            certificate="whatever certificate",
            private_key="whatever private key",
        )

        self._set_other_node_api_address_in_peer_relation(
            relation_id=peer_relation_id, unit_name=other_unit_name
        )

        self.harness.evaluate_status()

        self.assertEqual(self.harness.charm.unit.status, ops.model.ActiveStatus())

    @patch("ops.model.Model.get_binding")
    def test_given_unit_is_leader_when_authorize_charm_then_approle_configured_and_secrets_stored(
        self,
        mock_get_binding: MagicMock,
    ):
        self.mock_machine.exists.return_value = False
        mock_get_binding.return_value = MockBinding(bind_address="1.2.1.2")
        peer_relation_id = self._set_peer_relation()
        other_unit_name = f"{self.harness.charm.app.name}/1"
        self.harness.add_relation_unit(
            relation_id=peer_relation_id, remote_unit_name=other_unit_name
        )

        self._set_other_node_api_address_in_peer_relation(
            relation_id=peer_relation_id, unit_name=other_unit_name
        )
        self.harness.set_leader(is_leader=True)
        self.mock_vault.configure_mock(
            spec=Vault,
            **{
                "configure_approle.return_value": "approle_id",
                "generate_role_secret_id.return_value": "secret_id",
            },
        )

        self.harness.run_action("authorize-charm", {"token": "test-token"})

        # Assertions
        self.mock_vault.authenticate.assert_called_once_with(Token("test-token"))
        self.mock_vault.enable_audit_device.assert_called_once_with(
            device_type=AuditDeviceType.FILE, path="stdout"
        )
        self.mock_vault.enable_approle_auth_method.assert_called_once()
        self.mock_vault.configure_policy.assert_called_once_with(
            policy_name=VAULT_CHARM_POLICY_NAME, policy_path=VAULT_CHARM_POLICY_PATH
        )
        self.mock_vault.configure_approle.assert_called_once_with(
            role_name="charm", policies=[VAULT_CHARM_POLICY_NAME, VAULT_DEFAULT_POLICY_NAME]
        )
        self.mock_vault.generate_role_secret_id.assert_called_once_with(name="charm")

        secret_content = self.harness.model.get_secret(
            label=VAULT_CHARM_APPROLE_SECRET_LABEL
        ).get_content()

        assert secret_content["role-id"] == "approle_id"
        assert secret_content["secret-id"] == "secret_id"

    @patch("charm.get_common_name_from_certificate", new=Mock)
    @patch(f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.request_certificate_creation")
    @patch("ops.model.Model.get_binding")
    def test_given_vault_is_available_when_tls_certificates_pki_relation_joined_then_certificate_request_is_made(
        self,
        patch_get_binding,
        patch_request_certificate_creation,
    ):
        self._set_peer_relation()
        patch_get_binding.return_value = MockBinding(bind_address="1.2.1.2")
        csr = "some csr content"
        self.harness.charm.app.add_secret(
            {"role-id": "role-id", "secret-id": "secret-id"},
            label=VAULT_CHARM_APPROLE_SECRET_LABEL,
        )
        self.mock_vault.configure_mock(
            spec=Vault,
            **{
                "is_initialized.return_value": True,
                "is_api_available.return_value": True,
                "is_sealed.return_value": False,
                "get_intermediate_ca.return_value": "vault",
                "generate_pki_intermediate_ca_csr.return_value": csr,
            },
        )
        self.harness.update_config({"common_name": "vault"})
        self.harness.set_leader(is_leader=True)
        relation_id = self.harness.add_relation(
            relation_name=TLS_CERTIFICATES_PKI_RELATION_NAME, remote_app="tls-provider"
        )

        self.harness.add_relation_unit(relation_id, "tls-provider/0")

        self.mock_vault.enable_secrets_engine.assert_called_with(SecretsBackend.PKI, "charm-pki")
        self.mock_vault.generate_pki_intermediate_ca_csr.assert_called_with(
            mount="charm-pki", common_name="vault"
        )
        patch_request_certificate_creation.assert_called_with(
            certificate_signing_request=csr.encode(), is_ca=True
        )

    @patch("ops.model.Model.get_binding")
    @patch(f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.get_assigned_certificates")
    def test_given_vault_is_available_when_pki_certificate_is_available_then_certificate_added_to_vault_pki(
        self,
        patch_get_assigned_certificates,
        patch_get_binding,
    ):
        peer_relation_id = self._set_peer_relation()
        patch_get_binding.return_value = MockBinding(bind_address="1.2.1.2")
        self.harness.charm.app.add_secret(
            {"role-id": "role-id", "secret-id": "secret-id"},
            label=VAULT_CHARM_APPROLE_SECRET_LABEL,
        )
        self.mock_vault.configure_mock(
            spec=Vault,
            **{
                "is_initialized.return_value": True,
                "is_api_available.return_value": True,
                "is_sealed.return_value": False,
                "is_intermediate_ca_set.return_value": False,
                "is_pki_role_created.return_value": False,
            },
        )

        csr = "some csr content"
        certificate = "some certificate"
        ca = "some ca"
        chain = [ca]
        self.harness.update_config({"common_name": "vault"})
        self.harness.set_leader(is_leader=True)

        self._set_csr_secret_in_peer_relation(relation_id=peer_relation_id, csr="some csr content")
        event = CertificateAvailableEvent(
            handle=Mock(),
            certificate=certificate,
            certificate_signing_request=csr,
            ca=ca,
            chain=chain,
        )
        relation_id = self.harness.add_relation(
            relation_name=TLS_CERTIFICATES_PKI_RELATION_NAME, remote_app="tls-provider"
        )
        patch_get_assigned_certificates.return_value = [
            ProviderCertificate(
                relation_id=relation_id,
                application_name="tls-provider",
                csr=csr,
                certificate=certificate,
                ca=ca,
                chain=chain,
                revoked=False,
            )
        ]

        self.harness.charm._on_tls_certificate_pki_certificate_available(event)

        self.mock_vault.set_pki_intermediate_ca_certificate.assert_called_with(
            certificate=certificate,
            mount="charm-pki",
        )
        self.mock_vault.create_pki_charm_role.assert_called_with(
            allowed_domains="vault", mount="charm-pki", role="charm-pki"
        )
