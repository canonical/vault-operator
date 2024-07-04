# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import unittest
from datetime import datetime, timezone
from typing import Mapping
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
    CertificateCreationRequestEvent,
    ProviderCertificate,
)
from charms.vault_k8s.v0.vault_autounseal import AutounsealDetails
from charms.vault_k8s.v0.vault_client import (
    AppRole,
    AuditDeviceType,
    Certificate,
    SecretsBackend,
    Token,
    Vault,
    VaultClientError,
)
from charms.vault_k8s.v0.vault_s3 import S3, S3Error
from charms.vault_k8s.v0.vault_tls import CA_CERTIFICATE_JUJU_SECRET_LABEL, VaultTLSManager

S3_LIB_PATH = "charms.data_platform_libs.v0.s3"
PEER_RELATION_NAME = "vault-peers"
VAULT_KV_RELATION_NAME = "vault-kv"
S3_RELATION_NAME = "s3-parameters"
VAULT_STORAGE_PATH = "/var/snap/vault/common/raft"
TLS_CERTIFICATES_LIB_PATH = "charms.tls_certificates_interface.v3.tls_certificates"
VAULT_KV_LIB_PATH = "charms.vault_k8s.v0.vault_kv"
TLS_CERTIFICATES_PKI_RELATION_NAME = "tls-certificates-pki"
VAULT_KV_REQUIRER_APPLICATION_NAME = "vault-kv-requirer"
VAULT_AUTOUNSEAL_LIB_PATH = "charms.vault_k8s.v0.vault_autounseal"
AUTOUNSEAL_MOUNT_PATH = "charm-autounseal"


class MockNetwork:
    def __init__(self, bind_address: str, ingress_address: str):
        self.bind_address = bind_address
        self.ingress_address = ingress_address


class MockBinding:
    def __init__(self, bind_address: str, ingress_address: str):
        self.network = MockNetwork(bind_address=bind_address, ingress_address=ingress_address)


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
    patcher_vault_tls_manager = patch("charm.VaultTLSManager", autospec=VaultTLSManager)
    patcher_machine = patch("charm.Machine")
    patcher_vault = patch("charm.Vault", autospec=Vault)

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

    def get_valid_s3_params(self) -> Mapping[str, str]:
        """Return a valid S3 parameters for mocking."""
        return {
            "bucket": "BUCKET",
            "access-key": "whatever access key",
            "secret-key": "whatever secret key",
            "endpoint": "http://ENDPOINT",
            "region": "REGION",
        }

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

    def _set_approle_secret(self, role_id: str, secret_id: str) -> None:
        """Set the approle secret."""
        content = {
            "role-id": role_id,
            "secret-id": secret_id,
        }
        original_leader_state = self.harness.charm.unit.is_leader()
        with self.harness.hooks_disabled():
            self.harness.set_leader(is_leader=True)
            secret_id = self.harness.add_model_secret(owner=self.app_name, content=content)
            secret = self.harness.model.get_secret(id=secret_id)
            secret.set_info(label=VAULT_CHARM_APPROLE_SECRET_LABEL)
            self.harness.set_leader(original_leader_state)

    def setup_vault_kv_relation(self) -> tuple:
        app_name = VAULT_KV_REQUIRER_APPLICATION_NAME
        unit_name = app_name + "/0"
        relation_name = VAULT_KV_RELATION_NAME

        host_ip = "10.20.20.1"
        self.harness.add_network(host_ip, endpoint="vault-kv")
        self.harness.set_leader()
        rel_id = self.harness.add_relation(relation_name, app_name)
        unit_name = app_name + "/0"
        egress_subnet = "10.20.20.20/32"
        self.harness.add_relation_unit(rel_id, unit_name)
        self.harness.update_relation_data(
            rel_id, unit_name, {"egress_subnet": egress_subnet, "nonce": "0"}
        )

        return (rel_id, egress_subnet)

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
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2", ingress_address="2.3.2.3"
        )

        self.harness.charm.on.install.emit()

        self.mock_snap_cache.assert_called_with()
        vault_snap.ensure.assert_called_with(
            SnapState.Latest, channel="1.15/stable", revision="2226"
        )
        vault_snap.hold.assert_called()

    @patch("ops.model.Model.get_binding")
    def test_given_config_file_not_exists_when_configure_then_config_file_pushed(
        self, patch_get_binding
    ):
        self.harness.set_leader(is_leader=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        self.mock_machine.exists.return_value = False
        expected_content_hcl = hcl.loads(read_file("tests/unit/config.hcl"))
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2", ingress_address="2.3.2.3"
        )
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
    def test_given_unit_not_leader_and_peer_addresses_unavailable_when_collectstatus_then_status_is_waiting(  # noqa: E501
        self, patch_get_binding
    ):
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2", ingress_address="2.3.2.3"
        )
        self.mock_vault_tls_manager.tls_file_available_in_charm.return_value = False
        self.harness.set_leader(is_leader=False)
        self._set_peer_relation()

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.charm.unit.status,
            ops.WaitingStatus("Waiting for other units to provide their addresses"),
        )

    @patch("ops.model.Model.get_binding")
    def test_given_unit_is_leader_and_ca_certificate_saved_when_collectstatus_then_status_is_blocked(  # noqa: E501
        self,
        patch_get_binding,
    ):
        self.mock_vault.configure_mock(**{"needs_migration.return_value": False})
        self.mock_machine.exists.return_value = False
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2", ingress_address="2.3.2.3"
        )
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
            ops.BlockedStatus("Please unseal Vault"),
        )

    @patch("charm.config_file_content_matches", new=Mock())
    @patch("ops.model.Model.get_binding")
    def test_given_vault_snap_installed_when_configure_then_directories_created(
        self,
        patch_get_binding,
    ):
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2", ingress_address="2.3.2.3"
        )
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
        patch_get_binding.return_value = MockBinding(
            bind_address=bind_address, ingress_address="2.3.2.3"
        )
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
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2", ingress_address="2.3.2.3"
        )
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
    def test_given_unit_not_leader_and_peer_addresses_available_and_vault_unsealed_when_collectstatus_then_status_is_active(  # noqa: E501
        self,
        patch_get_binding,
    ):
        self.mock_vault.configure_mock(**{"is_sealed.return_value": False})

        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2", ingress_address="2.3.2.3"
        )
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
        mock_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2", ingress_address="2.3.2.3"
        )
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

        action_result = self.harness.run_action("authorize-charm", {"token": "test-token"}).results

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
            role_name="charm",
            policies=[VAULT_CHARM_POLICY_NAME, VAULT_DEFAULT_POLICY_NAME],
            token_ttl="1h",
            token_max_ttl="1h",
        )
        self.mock_vault.generate_role_secret_id.assert_called_once_with(name="charm")

        secret_content = self.harness.model.get_secret(
            label=VAULT_CHARM_APPROLE_SECRET_LABEL
        ).get_content(refresh=True)

        assert secret_content["role-id"] == "approle_id"
        assert secret_content["secret-id"] == "secret_id"
        assert action_result["result"] == "Charm authorized successfully."

    @patch("charm.get_common_name_from_certificate", new=Mock)
    @patch(f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.request_certificate_creation")
    @patch("ops.model.Model.get_binding")
    def test_given_vault_is_available_when_tls_certificates_pki_relation_joined_then_certificate_request_is_made(  # noqa: E501
        self,
        patch_get_binding,
        patch_request_certificate_creation,
    ):
        self._set_peer_relation()
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2", ingress_address="2.3.2.3"
        )
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

    @patch("charm.config_file_content_matches", new=Mock())
    @patch("charm.get_common_name_from_certificate", new=Mock)
    @patch(f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.request_certificate_creation")
    @patch("ops.model.Model.get_binding")
    def test_given_vault_pki_configured_when_common_name_is_changed_then_new_certificate_request_is_made(  # noqa: E501
        self,
        patch_get_binding,
        patch_request_certificate_creation,
    ):
        self._set_peer_relation()
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2", ingress_address="2.3.2.3"
        )
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

        self.harness.update_config({"common_name": "new_common_name"})
        self.mock_vault.generate_pki_intermediate_ca_csr.assert_called_with(
            mount="charm-pki", common_name="new_common_name"
        )
        patch_request_certificate_creation.assert_called_with(
            certificate_signing_request=csr.encode(), is_ca=True
        )

    @patch("charm.get_common_name_from_certificate")
    @patch("ops.model.Model.get_binding")
    @patch(f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.get_assigned_certificates")
    def test_given_vault_is_available_when_pki_certificate_is_available_then_certificate_added_to_vault_pki(  # noqa: E501
        self,
        patch_get_assigned_certificates,
        patch_get_binding,
        patch_get_common_name_from_certificate,
    ):
        peer_relation_id = self._set_peer_relation()
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2", ingress_address="2.3.2.3"
        )
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
                "is_common_name_allowed_in_pki_role.return_value": False,
            },
        )

        csr = "some csr content"
        certificate = "some certificate"
        ca = "some ca"
        chain = [ca]
        common_name = "vault"
        patch_get_common_name_from_certificate.return_value = common_name
        self.harness.update_config({"common_name": common_name})
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
                expiry_time=datetime.now(timezone.utc),
            )
        ]

        self.harness.charm._on_tls_certificate_pki_certificate_available(event)

        self.mock_vault.set_pki_intermediate_ca_certificate.assert_called_with(
            certificate=certificate,
            mount="charm-pki",
        )
        self.mock_vault.create_or_update_pki_charm_role.assert_called_with(
            allowed_domains="vault", mount="charm-pki", role="charm-pki"
        )

    @patch("charm.config_file_content_matches", new=Mock())
    @patch("charm.get_common_name_from_certificate")
    @patch("ops.model.Model.get_binding")
    @patch(f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.get_assigned_certificates")
    def test_given_vault_pki_configured_when_common_name_is_changed_then_new_certificate_added_to_vault_pki(  # noqa: E501
        self,
        patch_get_assigned_certificates,
        patch_get_binding,
        patch_get_common_name_from_certificate,
    ):
        peer_relation_id = self._set_peer_relation()
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2", ingress_address="2.3.2.3"
        )
        self.harness.charm.app.add_secret(
            {"role-id": "role-id", "secret-id": "secret-id"},
            label=VAULT_CHARM_APPROLE_SECRET_LABEL,
        )
        csr = "some csr content"
        certificate = "some certificate"
        ca = "some ca"
        chain = [ca]
        common_name = "vault"
        self.mock_vault.configure_mock(
            spec=Vault,
            **{
                "is_initialized.return_value": True,
                "is_api_available.return_value": True,
                "is_sealed.return_value": False,
                "is_intermediate_ca_set.return_value": False,
                "is_pki_role_created.return_value": False,
                "is_common_name_allowed_in_pki_role.return_value": False,
                "generate_pki_intermediate_ca_csr.return_value": csr,
            },
        )

        patch_get_common_name_from_certificate.return_value = common_name
        self.harness.update_config({"common_name": common_name})
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
                expiry_time=datetime.now(timezone.utc),
            )
        ]

        self.harness.charm._on_tls_certificate_pki_certificate_available(event)

        self.mock_vault.set_pki_intermediate_ca_certificate.assert_called_with(
            certificate=certificate,
            mount="charm-pki",
        )
        self.mock_vault.create_or_update_pki_charm_role.assert_called_with(
            allowed_domains="vault", mount="charm-pki", role="charm-pki"
        )

        self.harness.update_config({"common_name": "new_common_name"})

        self.harness.charm._on_tls_certificate_pki_certificate_available(event)

        self.mock_vault.set_pki_intermediate_ca_certificate.assert_called_with(
            certificate=certificate,
            mount="charm-pki",
        )
        self.mock_vault.create_or_update_pki_charm_role.assert_called_with(
            allowed_domains="new_common_name", mount="charm-pki", role="charm-pki"
        )

    @patch("ops.model.Model.get_binding")
    @patch(f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesProvidesV3.set_relation_certificate")
    @patch("charm.get_common_name_from_csr")
    def test_given_vault_available_when_vault_pki_certificate_creation_request_then_certificate_is_provided(  # noqa: E501
        self,
        patch_get_common_name_from_csr,
        patch_set_relation_certificate,
        patch_get_binding,
    ):
        self._set_peer_relation()

        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2", ingress_address="2.3.2.3"
        )
        self.harness.charm.app.add_secret(
            {"role-id": "role-id", "secret-id": "secret-id"},
            label=VAULT_CHARM_APPROLE_SECRET_LABEL,
        )
        csr = "some csr content"
        certificate = "some certificate"
        ca = "some ca"
        chain = [ca]
        self.mock_vault.configure_mock(
            spec=Vault,
            **{
                "is_initialized.return_value": True,
                "is_api_available.return_value": True,
                "is_pki_role_created.return_value": True,
                "is_sealed.return_value": False,
                "sign_pki_certificate_signing_request.return_value": Certificate(
                    certificate=certificate,
                    ca=ca,
                    chain=chain,
                ),
            },
        )
        relation_id = self.harness.add_relation(
            relation_name=TLS_CERTIFICATES_PKI_RELATION_NAME, remote_app="tls-provider"
        )
        common_name = "vault"
        relation_id = 99
        patch_get_common_name_from_csr.return_value = common_name
        self.harness.update_config({"common_name": common_name})
        self.harness.set_leader(is_leader=True)

        event = CertificateCreationRequestEvent(
            handle=Mock(),
            certificate_signing_request=csr,
            relation_id=relation_id,
            is_ca=False,
        )

        self.harness.charm._on_vault_pki_certificate_creation_request(event=event)

        self.mock_vault.sign_pki_certificate_signing_request.assert_called_with(
            mount="charm-pki",
            csr=csr,
            role="charm-pki",
            common_name=common_name,
        )

        patch_set_relation_certificate.assert_called_with(
            relation_id=relation_id,
            certificate_signing_request=csr,
            certificate=certificate,
            ca=ca,
            chain=chain,
        )

    @patch("charm.get_common_name_from_certificate")
    @patch("ops.model.Model.get_binding")
    @patch(f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.get_assigned_certificates")
    def test_given_vault_is_available_when_pki_certificate_is_available_then_default_issuer_is_set_to_latest_issuer(  # noqa: E501
        self,
        patch_get_assigned_certificates,
        patch_get_binding,
        patch_get_common_name_from_certificate,
    ):
        peer_relation_id = self._set_peer_relation()
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2", ingress_address="2.3.2.3"
        )
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
                "is_common_name_allowed_in_pki_role.return_value": False,
            },
        )

        csr = "some csr content"
        certificate = "some certificate"
        ca = "some ca"
        chain = [ca]
        common_name = "vault"
        patch_get_common_name_from_certificate.return_value = common_name
        self.harness.update_config({"common_name": common_name})
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
                expiry_time=datetime.now(timezone.utc),
            )
        ]

        self.harness.charm._on_tls_certificate_pki_certificate_available(event)

        self.mock_vault.set_pki_intermediate_ca_certificate.assert_called_with(
            certificate=certificate,
            mount="charm-pki",
        )
        self.mock_vault.create_or_update_pki_charm_role.assert_called_with(
            allowed_domains="vault", mount="charm-pki", role="charm-pki"
        )
        self.mock_vault.make_latest_pki_issuer_default.assert_called_with(mount="charm-pki")

    @patch("ops.model.Model.get_binding")
    def test_given_prerequisites_are_met_when_new_vault_kv_client_attached_then_kv_mount_is_configured(  # noqa: E501
        self,
        patch_get_binding,
    ):
        self.mock_vault_tls_manager.pull_tls_file_from_workload.return_value = "whatever ca cert"
        self.mock_vault.configure_mock(
            spec=Vault,
            **{
                "configure_approle.return_value": "12345678",
                "generate_role_secret_id.return_value": "11111111",
                "is_initialized.return_value": True,
                "is_api_available.return_value": True,
                "is_sealed.return_value": False,
            },
        )
        self._set_peer_relation()
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2", ingress_address="2.3.2.3"
        )
        self.harness.charm.app.add_secret(
            {"role-id": "role-id", "secret-id": "secret-id"},
            label=VAULT_CHARM_APPROLE_SECRET_LABEL,
        )
        self.harness.set_leader(is_leader=True)
        rel_id, _ = self.setup_vault_kv_relation()
        event = Mock()
        event.relation_name = VAULT_KV_RELATION_NAME
        event.relation_id = rel_id
        event.app_name = VAULT_KV_REQUIRER_APPLICATION_NAME
        event.unit_name = f"{VAULT_KV_REQUIRER_APPLICATION_NAME}/0"
        event.mount_suffix = "suffix"
        event.egress_subnet = "2.2.2.0/24"
        event.nonce = "123123"

        self.harness.charm._on_new_vault_kv_client_attached(event)

        self.mock_vault.enable_secrets_engine.assert_called_with(
            SecretsBackend.KV_V2, "charm-vault-kv-requirer-suffix"
        )
        self.mock_vault.configure_policy.assert_called_with(
            policy_name="charm-vault-kv-requirer-suffix-vault-kv-requirer-0",
            policy_path="src/templates/kv_mount.hcl",
            mount="charm-vault-kv-requirer-suffix",
        )
        self.mock_vault.configure_approle.assert_called_with(
            role_name="charm-vault-kv-requirer-suffix-vault-kv-requirer-0",
            policies=["charm-vault-kv-requirer-suffix-vault-kv-requirer-0"],
            cidrs=["2.2.2.0/24"],
            token_ttl="1h",
            token_max_ttl="1h",
        )
        self.mock_vault.generate_role_secret_id.assert_called_with(
            name="charm-vault-kv-requirer-suffix-vault-kv-requirer-0",
            cidrs=["2.2.2.0/24"],
        )

    def test_given_s3_relation_not_created_when_create_backup_action_then_action_fails(self):
        self.harness.set_leader(is_leader=True)

        with self.assertRaises(ops.testing.ActionFailed) as e:
            self.harness.run_action("create-backup")

        self.assertEqual(
            e.exception.message, "S3 pre-requisites not met. S3 relation not created."
        )

    def test_given_unit_not_leader_when_create_backup_action_then_action_fails(self):
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(ops.testing.ActionFailed) as e:
            self.harness.run_action("create-backup")

        self.assertEqual(
            e.exception.message,
            "S3 pre-requisites not met. Only leader unit can perform backup operations.",
        )

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_missing_s3_parameters_when_create_backup_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
    ):
        patch_get_s3_connection_info.return_value = {}
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(ops.testing.ActionFailed) as e:
            self.harness.run_action("create-backup")

        self.assertEqual(
            e.exception.message,
            "S3 pre-requisites not met. S3 parameters missing (bucket, access-key, secret-key, endpoint).",  # noqa: E501
        )

    @patch("charm.S3")
    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_s3_session_not_created_when_create_backup_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
        patch_s3,
    ):
        patch_s3.side_effect = S3Error("Failed to create S3 session.")
        patch_get_s3_connection_info.return_value = {
            "bucket": "whatever bucket",
            "access-key": "whatever access key",
            "secret-key": "whatever secret key",
            "endpoint": "whatever endpoint",
        }
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(ops.testing.ActionFailed) as e:
            self.harness.run_action("create-backup")

        self.assertEqual(e.exception.message, "Failed to create S3 session.")

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch("charm.S3")
    def test_given_bucket_creation_returns_false_when_create_backup_action_then_action_fails(
        self,
        patch_s3,
        patch_get_s3_connection_info,
    ):
        patch_s3.configure_mock(spec=S3, **{"return_value.create_bucket.return_value": False})
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(ops.testing.ActionFailed) as e:
            self.harness.run_action("create-backup")

        self.assertEqual(e.exception.message, "Failed to create S3 bucket.")

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch("charm.S3")
    def test_given_vault_is_not_initialized_when_create_backup_action_then_action_fails(
        self,
        patch_s3,
        patch_get_s3_connection_info,
    ):
        self.mock_vault.configure_mock(
            spec=Vault,
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": False,
            },
        )
        patch_s3.configure_mock(spec=S3, **{"return_value.create_bucket.return_value": True})
        self._set_peer_relation()
        self._set_ca_certificate_secret(
            certificate="whatever certificate",
            private_key="whatever private key",
        )
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(ops.testing.ActionFailed) as e:
            self.harness.run_action("create-backup")

        self.assertEqual(e.exception.message, "Failed to initialize Vault client.")

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch("charm.S3")
    def test_given_vault_api_not_available_when_create_backup_action_then_action_fails(
        self,
        patch_s3,
        patch_get_s3_connection_info,
    ):
        self.mock_vault.configure_mock(
            spec=Vault,
            **{
                "is_api_available.return_value": False,
                "is_initialized.return_value": True,
            },
        )
        patch_s3.configure_mock(spec=S3, **{"return_value.create_bucket.return_value": True})
        self._set_peer_relation()
        self._set_ca_certificate_secret(
            certificate="whatever certificate",
            private_key="whatever private key",
        )
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(ops.testing.ActionFailed) as e:
            self.harness.run_action("create-backup")

        self.assertEqual(e.exception.message, "Failed to initialize Vault client.")

    @patch("ops.model.Model.get_binding")
    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch("charm.S3")
    def test_given_s3_content_upload_fails_when_create_backup_action_then_action_fails(
        self,
        patch_s3,
        patch_get_s3_connection_info,
        patch_get_binding,
    ):
        self.harness.charm.app.add_secret(
            {"role-id": "role-id", "secret-id": "secret-id"},
            label=VAULT_CHARM_APPROLE_SECRET_LABEL,
        )
        self.mock_vault.configure_mock(
            spec=Vault,
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": True,
                "is_sealed.return_value": False,
            },
        )
        patch_s3.configure_mock(
            spec=S3,
            **{
                "return_value.create_bucket.return_value": True,
                "return_value.upload_content.return_value": False,
            },
        )
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.3.4", ingress_address="2.2.2.2"
        )

        self._set_peer_relation()
        self._set_ca_certificate_secret(
            certificate="whatever certificate",
            private_key="whatever private key",
        )
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(ops.testing.ActionFailed) as e:
            self.harness.run_action("create-backup")

        self.assertEqual(e.exception.message, "Failed to upload backup to S3 bucket.")

    @patch("ops.model.Model.get_binding")
    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch("charm.S3")
    def test_given_content_uploaded_to_s3_when_create_backup_action_then_action_succeeds(
        self,
        patch_s3,
        patch_get_s3_connection_info,
        patch_get_binding,
    ):
        self.harness.charm.app.add_secret(
            {"role-id": "role-id", "secret-id": "secret-id"},
            label=VAULT_CHARM_APPROLE_SECRET_LABEL,
        )
        self.mock_vault.configure_mock(
            spec=Vault,
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": True,
                "is_sealed.return_value": False,
            },
        )
        patch_s3.configure_mock(
            spec=S3,
            **{
                "return_value.create_bucket.return_value": True,
                "return_value.upload_content.return_value": True,
            },
        )
        patch_get_binding.return_value = MockBinding(
            bind_address="1.1.1.1", ingress_address="2.2.2.2"
        )

        self._set_peer_relation()
        self._set_ca_certificate_secret(
            certificate="whatever certificate",
            private_key="whatever private key",
        )
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        action_output = self.harness.run_action("create-backup")
        self.assertIn("backup-id", action_output.results)
        backup_id = action_output.results["backup-id"]
        self.assertIn(f"vault-backup-{self.model_name}", backup_id)

    def test_given_s3_relation_not_created_when_list_backup_action_then_action_fails(self):
        self.harness.set_leader(is_leader=True)

        with self.assertRaises(ops.testing.ActionFailed) as e:
            self.harness.run_action("list-backups")

        self.assertEqual(
            e.exception.message, "S3 pre-requisites not met. S3 relation not created."
        )

    def test_given_unit_not_leader_when_list_backups_action_then_action_fails(self):
        with self.assertRaises(ops.testing.ActionFailed) as e:
            self.harness.run_action("list-backups")

        self.assertEqual(
            e.exception.message,
            "S3 pre-requisites not met. Only leader unit can perform backup operations.",
        )

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_missing_s3_parameters_when_list_backups_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
    ):
        patch_get_s3_connection_info.return_value = {}
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(ops.testing.ActionFailed) as e:
            self.harness.run_action("list-backups")

        self.assertEqual(
            e.exception.message,
            "S3 pre-requisites not met. S3 parameters missing (bucket, access-key, secret-key, endpoint).",  # noqa: E501
        )

    @patch("charm.S3")
    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_s3_session_not_created_when_list_backups_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
        patch_s3,
    ):
        patch_s3.side_effect = S3Error("Failed to create S3 session.")
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(ops.testing.ActionFailed) as e:
            self.harness.run_action("list-backups")

        self.assertEqual(e.exception.message, "Failed to create S3 session.")

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch("charm.S3")
    def test_given_s3_list_objects_fails_when_list_backups_action_then_action_fails(
        self,
        patch_s3,
        patch_get_s3_connection_info,
    ):
        patch_s3.configure_mock(
            spec=S3,
            **{"return_value.get_object_key_list.side_effect": S3Error("Failed to list objects.")},
        )
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(ops.testing.ActionFailed) as e:
            self.harness.run_action("list-backups")

        self.assertEqual(
            e.exception.message, "Failed to run list-backups action - Failed to list backups."
        )

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch("charm.S3")
    def test_given_s3_list_objects_succeeds_when_list_backups_action_then_action_succeeds(
        self,
        patch_s3,
        patch_get_s3_connection_info,
    ):
        patch_s3.configure_mock(
            spec=S3, **{"return_value.get_object_key_list.return_value": ["backup1", "backup2"]}
        )
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        action_output = self.harness.run_action("list-backups")

        self.assertIn("backup-ids", action_output.results)
        backup_ids = action_output.results["backup-ids"]
        self.assertEqual(backup_ids, json.dumps(["backup1", "backup2"]))

    def test_given_s3_relation_not_created_when_restore_backup_action_then_action_fails(self):
        self.harness.set_leader(is_leader=True)

        with self.assertRaises(ops.testing.ActionFailed) as e:
            self.harness.run_action("restore-backup", params={"backup-id": "backup-id"})

        self.assertEqual(
            e.exception.message, "S3 pre-requisites not met. S3 relation not created."
        )

    def test_given_unit_not_leader_when_restore_backup_action_then_action_fails(self):
        with self.assertRaises(ops.testing.ActionFailed) as e:
            self.harness.run_action("restore-backup", params={"backup-id": "backup-id"})

        self.assertEqual(
            e.exception.message,
            "S3 pre-requisites not met. Only leader unit can perform backup operations.",
        )

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_missing_s3_parameters_when_restore_backup_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
    ):
        patch_get_s3_connection_info.return_value = {}
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(ops.testing.ActionFailed) as e:
            self.harness.run_action("restore-backup", params={"backup-id": "backup-id"})

        self.assertEqual(
            e.exception.message,
            "S3 pre-requisites not met. S3 parameters missing (bucket, access-key, secret-key, endpoint).",  # noqa: E501
        )

    @patch("charm.S3")
    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_s3_session_not_created_when_restore_backup_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
        patch_s3,
    ):
        patch_s3.side_effect = S3Error("Failed to create S3 session.")
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(ops.testing.ActionFailed) as e:
            self.harness.run_action("restore-backup", params={"backup-id": "backup-id"})

        self.assertEqual(e.exception.message, "Failed to create S3 session.")

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch("charm.S3")
    def test_given_s3_error_when_restore_backup_action_then_action_fails(
        self,
        patch_s3,
        patch_get_s3_connection_info,
    ):
        patch_s3.configure_mock(
            spec=S3,
            **{
                "return_value.get_content.side_effect": S3Error(
                    "Failed to retrieve snapshot from S3 storage."
                )
            },
        )
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(ops.testing.ActionFailed) as e:
            self.harness.run_action("restore-backup", params={"backup-id": "backup-id"})

        self.assertEqual(e.exception.message, "Failed to retrieve snapshot from S3 storage.")

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch("charm.S3")
    def test_given_no_returned_snapshot_from_s3_when_restore_backup_action_then_action_fails(
        self,
        patch_s3,
        patch_get_s3_connection_info,
    ):
        patch_s3.configure_mock(spec=S3, **{"return_value.get_content.return_value": None})
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(ops.testing.ActionFailed) as e:
            self.harness.run_action("restore-backup", params={"backup-id": "backup-id"})

        self.assertEqual(e.exception.message, "Backup not found in S3 bucket.")

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch("charm.S3")
    def test_given_vault_api_not_available_when_restore_backup_action_then_action_fails(
        self,
        patch_s3,
        patch_get_s3_connection_info,
    ):
        self.mock_vault.configure_mock(
            spec=Vault,
            **{
                "is_api_available.return_value": False,
                "is_initialized.return_value": True,
            },
        )
        patch_s3.configure_mock(spec=S3, **{"return_value.get_content.return_value": "snapshot"})
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(ops.testing.ActionFailed) as e:
            self.harness.run_action("restore-backup", params={"backup-id": "backup-id"})

        self.assertEqual(
            e.exception.message, "Failed to restore vault. Vault API is not available."
        )

    @patch("ops.model.Model.get_binding")
    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch("charm.S3")
    def test_given_vault_client_error_when_restore_backup_action_then_action_fails(
        self, patch_s3, patch_get_s3_connection_info, patch_get_binding
    ):
        self.harness.charm.app.add_secret(
            {"role-id": "role-id", "secret-id": "secret-id"},
            label=VAULT_CHARM_APPROLE_SECRET_LABEL,
        )
        self._set_peer_relation()
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.3.4", ingress_address="2.2.2.2"
        )
        self.mock_vault.configure_mock(
            spec=Vault,
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": True,
                "is_sealed.return_value": False,
                "restore_snapshot.side_effect": VaultClientError(),
            },
        )
        patch_s3.configure_mock(spec=S3, **{"return_value.get_content.return_value": "snapshot"})
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(ops.testing.ActionFailed) as e:
            self.harness.run_action("restore-backup", params={"backup-id": "backup-id"})

        self.assertEqual(e.exception.message, "Failed to restore vault.")

    # Test remove
    @patch("ops.model.Model.get_binding")
    def test_given_vault_unsealed_when_on_remove_then_node_removed_from_raft_cluster(
        self,
        patch_get_binding,
    ):
        self._set_peer_relation()
        self.harness.charm.app.add_secret(
            {"role-id": "role-id", "secret-id": "secret-id"},
            label=VAULT_CHARM_APPROLE_SECRET_LABEL,
        )
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.3.4", ingress_address="2.2.2.2"
        )
        self.mock_vault.configure_mock(
            spec=Vault,
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": True,
                "is_sealed.return_value": False,
                "get_num_raft_peers.return_value": 3,
            },
        )

        self.harness.charm.on.remove.emit()

        self.mock_vault.remove_raft_node.assert_called_once()

    def test_when_on_remove_then_raft_dbs_are_removed(self):
        self.harness.charm.on.remove.emit()

        self.mock_machine.remove_path.assert_has_calls(
            calls=[
                call(path=f"{VAULT_STORAGE_PATH}/vault.db"),
                call(path=f"{VAULT_STORAGE_PATH}/raft/raft.db"),
            ]
        )

    @patch("ops.model.Model.get_binding")
    def test_given_ca_certificate_and_bind_address_are_available_when_generate_vault_scrape_configs_then_config_is_generated(  # noqa: E501
        self,
        patch_get_binding,
    ):
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2", ingress_address="2.3.2.3"
        )
        self.mock_vault_tls_manager.pull_tls_file_from_workload.return_value = "whatever ca cert"
        self._set_peer_relation()
        actual_config = self.harness.charm.generate_vault_scrape_configs()
        expected_config = [
            {
                "scheme": "https",
                "tls_config": {
                    "insecure_skip_verify": False,
                    "ca": "whatever ca cert",
                },
                "metrics_path": "/v1/sys/metrics",
                "static_configs": [{"targets": ["1.2.1.2:8200"]}],
            }
        ]
        self.assertEqual(
            actual_config,
            expected_config,
        )

    def test_given_bind_address_not_available_when_generate_vault_scrape_configs_then_config_is_empty(  # noqa: E501
        self,
    ):
        actual_config = self.harness.charm.generate_vault_scrape_configs()
        self.assertEqual(
            actual_config,
            [],
        )

    @patch("ops.testing._TestingPebbleClient.restart_services", new=MagicMock)
    @patch(f"{VAULT_AUTOUNSEAL_LIB_PATH}.VaultAutounsealRequires.get_details")
    def test_given_autounseal_details_available_when_autounseal_details_ready_then_transit_stanza_generated(  # noqa: E501
        self,
        mock_get_details,
    ):
        # Given
        address = "some address"
        key_name = "some key"
        role_id = "role_id"
        secret_id = "secret_id"
        ca_cert = "ca_cert"
        mock_get_details.return_value = AutounsealDetails(
            address, AUTOUNSEAL_MOUNT_PATH, key_name, role_id, secret_id, ca_cert
        )
        relation_id = self.harness.add_relation(
            relation_name="vault-autounseal-requires", remote_app="autounseal-provider"
        )
        self.harness.add_storage(storage_name="config", attach=True)
        self._set_peer_relation()
        self.harness.update_relation_data(
            app_or_unit=self.app_name,
            relation_id=relation_id,
            key_values={},
        )
        self.harness.set_leader()  # TODO: Why does this need to be set?
        self.mock_machine.exists.return_value = False
        self.mock_vault.token = "some token"

        # When
        self.harness.charm.vault_autounseal_requires.on.vault_autounseal_details_ready.emit(
            address, AUTOUNSEAL_MOUNT_PATH, key_name, role_id, secret_id, ca_cert
        )

        # Then
        self.mock_machine.push.assert_called()
        _, kwargs = self.mock_machine.push.call_args
        assert kwargs["path"] == "/var/snap/vault/common/vault.hcl"
        pushed_content_hcl = hcl.loads(kwargs["source"])
        assert pushed_content_hcl["seal"]["transit"]["address"] == address
        assert pushed_content_hcl["seal"]["transit"]["mount_path"] == AUTOUNSEAL_MOUNT_PATH
        assert pushed_content_hcl["seal"]["transit"]["key_name"] == "some key"
        assert pushed_content_hcl["seal"]["transit"]["token"] == "some token"
        self.mock_vault.authenticate.assert_called_with(AppRole(role_id, secret_id))
        self.mock_vault_tls_manager.push_autounseal_ca_cert.assert_called_with(ca_cert)

    @patch(f"{VAULT_AUTOUNSEAL_LIB_PATH}.VaultAutounsealProvides.set_autounseal_data")
    def test_when_autounseal_initialize_then_credentials_are_set(self, mock_set_autounseal_data):
        # Given
        self.mock_vault.configure_mock(
            **{
                "is_initialized.return_value": True,
                "is_api_available.return_value": True,
                "is_sealed.return_value": False,
                "create_autounseal_credentials.return_value": (
                    "key name",
                    "autounseal role id",
                    "autounseal secret id",
                ),
            },
        )
        self.mock_machine.exists.return_value = False
        self.harness.set_leader()
        self.harness.add_storage(storage_name="config", attach=True)
        self._set_peer_relation()
        self._set_approle_secret("role id", "secret id")
        self.mock_vault_tls_manager.pull_tls_file_from_workload.return_value = "ca cert"
        # Set the default network
        self.harness.add_network("10.0.0.10")
        # # When
        relation_id = self.harness.add_relation(
            relation_name="vault-autounseal-provides", remote_app="autounseal-requirer"
        )

        # Then
        relation = self.harness.model.get_relation("vault-autounseal-provides", relation_id)
        mock_set_autounseal_data.assert_called_once_with(
            relation,
            "https://10.0.0.10:8200",
            AUTOUNSEAL_MOUNT_PATH,
            "key name",
            "autounseal role id",
            "autounseal secret id",
            "ca cert",
        )

    def test_given_autounseal_requirer_present_when_autounseal_destroy_then_credentials_are_removed(  # noqa: E501
        self,
    ):
        # Given
        self.mock_vault.configure_mock(
            **{
                "is_initialized.return_value": True,
                "is_api_available.return_value": True,
            },
        )
        self.mock_machine.exists.return_value = False
        self.harness.add_network("10.0.0.10")
        self._set_approle_secret("role id", "secret id")
        self._set_peer_relation()
        self.harness.set_leader()
        with self.harness.hooks_disabled():
            relation_id = self.harness.add_relation(
                relation_name="vault-autounseal-provides", remote_app="autounseal-requirer"
            )
            relation = self.harness.model.get_relation("vault-autounseal-provides", relation_id)

        # When
        self.harness.charm.vault_autounseal_provides.on.vault_autounseal_requirer_relation_broken.emit(
            relation
        )

        # Then
        self.mock_vault.destroy_autounseal_credentials.assert_called_once_with(
            relation_id, AUTOUNSEAL_MOUNT_PATH
        )
