#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import datetime
from io import StringIO
from unittest.mock import MagicMock

import hcl
import scenario
from charms.operator_libs_linux.v2.snap import Snap
from charms.tls_certificates_interface.v3.tls_certificates import (
    ProviderCertificate,
    RequirerCSR,
)
from charms.vault_k8s.v0.vault_client import Certificate, SecretsBackend

from tests.unit.fixtures import MockBinding, VaultCharmFixtures


class MockRelation:
    def __init__(self, id: int):
        self.id = id


class TestCharmConfigure(VaultCharmFixtures):
    def test_given_leader_when_configure_then_config_file_is_pushed(self):
        self.mock_socket_fqdn.return_value = "myhostname"
        self.mock_autounseal_requires_get_details.return_value = None
        self.mock_machine.pull.return_value = StringIO("")
        self.mock_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2",
            ingress_address="1.2.1.2",
        )
        model_name = "whatever"

        peer_relation = scenario.PeerRelation(
            endpoint="vault-peers",
        )
        state_in = scenario.State(
            leader=True,
            relations=[peer_relation],
            model=scenario.Model(name=model_name),
        )

        self.ctx.run("config-changed", state_in)

        with open("tests/unit/config.hcl", "r") as f:
            expected_config = f.read()
        _, kwargs = self.mock_machine.push.call_args
        assert kwargs["path"] == "/var/snap/vault/common/vault.hcl"
        pushed_content_hcl = hcl.loads(kwargs["source"])
        assert pushed_content_hcl == hcl.loads(expected_config)

    def test_given_leader_when_configure_then_vault_service_is_started(self):
        self.mock_autounseal_requires_get_details.return_value = None
        self.mock_machine.pull.return_value = StringIO("")
        self.mock_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2",
            ingress_address="1.2.1.2",
        )
        vault_snap = MagicMock(spec=Snap)
        snap_cache = {"vault": vault_snap}
        self.mock_snap_cache.return_value = snap_cache
        peer_relation = scenario.PeerRelation(
            endpoint="vault-peers",
        )
        state_in = scenario.State(
            leader=True,
            relations=[peer_relation],
        )

        self.ctx.run("config_changed", state_in)

        vault_snap.start.assert_called_with(services=["vaultd"])

    # PKI

    def test_given_vault_active_when_configure_then_pki_secrets_engine_is_configured(self):
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "authenticate.return_value": True,
                "is_initialized.return_value": True,
                "is_sealed.return_value": False,
                "is_active_or_standby.return_value": True,
                "generate_pki_intermediate_ca_csr.return_value": "my csr",
                "get_intermediate_ca.return_value": "",
            },
        )
        self.mock_pki_requirer_get_assigned_certificates.return_value = []
        self.mock_autounseal_requires_get_details.return_value = None
        self.mock_machine.pull.return_value = StringIO("")
        self.mock_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2",
            ingress_address="1.2.1.2",
        )
        peer_relation = scenario.PeerRelation(
            endpoint="vault-peers",
        )
        pki_relation = scenario.Relation(
            endpoint="tls-certificates-pki",
            interface="tls-certificates",
        )
        approle_secret = scenario.Secret(
            id="0",
            label="vault-approle-auth-details",
            contents={0: {"role-id": "role id", "secret-id": "secret id"}},
        )
        state_in = scenario.State(
            leader=True,
            secrets=[approle_secret],
            relations=[peer_relation, pki_relation],
            config={"common_name": "myhostname.com"},
        )

        self.ctx.run("config_changed", state_in)

        self.mock_vault.enable_secrets_engine.assert_called_once_with(
            SecretsBackend.PKI, "charm-pki"
        )
        self.mock_vault.generate_pki_intermediate_ca_csr.assert_called_once_with(
            mount="charm-pki",
            common_name="myhostname.com",
        )
        self.mock_pki_requirer_request_certificate_creation.assert_called_once_with(
            certificate_signing_request="my csr".encode(),
            is_ca=True,
        )

    def test_given_vault_is_available_when_configure_then_certificate_added_to_vault_pki_and_latest_issuer_set_to_default(
        self,
    ):
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "authenticate.return_value": True,
                "is_initialized.return_value": True,
                "is_sealed.return_value": False,
                "is_active_or_standby.return_value": True,
                "generate_pki_intermediate_ca_csr.return_value": "my csr",
                "is_common_name_allowed_in_pki_role.return_value": False,
                "get_intermediate_ca.return_value": "",
            },
        )
        self.mock_autounseal_requires_get_details.return_value = None
        self.mock_machine.pull.return_value = StringIO("")
        self.mock_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2",
            ingress_address="1.2.1.2",
        )
        peer_relation = scenario.PeerRelation(
            endpoint="vault-peers",
        )
        pki_relation = scenario.Relation(
            endpoint="tls-certificates-pki",
            interface="tls-certificates",
        )
        provider_certificate = ProviderCertificate(
            relation_id=pki_relation.relation_id,
            application_name="tls-provider",
            expiry_time=datetime.datetime.now(),
            certificate="my certificate",
            chain=["my ca"],
            csr="my csr",
            ca="my ca",
            revoked=False,
        )
        self.mock_pki_requirer_get_assigned_certificates.return_value = [provider_certificate]
        approle_secret = scenario.Secret(
            id="0",
            label="vault-approle-auth-details",
            contents={0: {"role-id": "role id", "secret-id": "secret id"}},
        )
        csr_secret = scenario.Secret(
            id="1",
            label="pki-csr",
            contents={0: {"csr": "my csr"}},
            owner="app",
        )
        state_in = scenario.State(
            leader=True,
            secrets=[approle_secret, csr_secret],
            relations=[peer_relation, pki_relation],
            config={"common_name": "myhostname.com"},
        )

        self.ctx.run("config_changed", state_in)

        self.mock_vault.set_pki_intermediate_ca_certificate.assert_called_once_with(
            certificate=provider_certificate.certificate,
            mount="charm-pki",
        )
        self.mock_vault.make_latest_pki_issuer_default.assert_called_once_with(
            mount="charm-pki",
        )
        self.mock_vault.create_or_update_pki_charm_role.assert_called_once_with(
            allowed_domains="myhostname.com",
            mount="charm-pki",
            role="charm-pki",
        )

    def test_given_vault_available_when_configure_then_certificate_is_provided(
        self,
    ):
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "authenticate.return_value": True,
                "is_initialized.return_value": True,
                "is_sealed.return_value": False,
                "is_active_or_standby.return_value": True,
                "generate_pki_intermediate_ca_csr.return_value": "my csr",
                "is_common_name_allowed_in_pki_role.return_value": False,
                "get_intermediate_ca.return_value": "",
                "sign_pki_certificate_signing_request.return_value": Certificate(
                    certificate="my certificate",
                    ca="my ca",
                    chain=["my ca"],
                ),
            },
        )
        self.mock_autounseal_requires_get_details.return_value = None
        self.mock_machine.pull.return_value = StringIO("")
        self.mock_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2",
            ingress_address="1.2.1.2",
        )
        peer_relation = scenario.PeerRelation(
            endpoint="vault-peers",
        )
        pki_relation_provider = scenario.Relation(
            endpoint="tls-certificates-pki",
            interface="tls-certificates",
            remote_app_name="tls-provider",
        )
        pki_relation_requirer = scenario.Relation(
            endpoint="vault-pki",
            interface="tls-certificates",
            remote_app_name="tls-requirer",
        )
        provider_certificate = ProviderCertificate(
            relation_id=pki_relation_provider.relation_id,
            application_name="tls-provider",
            expiry_time=datetime.datetime.now(),
            certificate="my certificate",
            chain=["my ca"],
            csr="my csr",
            ca="my ca",
            revoked=False,
        )
        requirer_csr = RequirerCSR(
            relation_id=pki_relation_requirer.relation_id,
            application_name="tls-requirer",
            unit_name="tls-requirer/0",
            csr="requirer csr",
            is_ca=False,
        )
        self.mock_pki_requirer_get_assigned_certificates.return_value = [provider_certificate]
        self.mock_pki_provider_get_outstanding_certificate_requests.return_value = [requirer_csr]
        self.mock_get_common_name_from_csr.return_value = "subdomain.myhostname.com"
        approle_secret = scenario.Secret(
            id="0",
            label="vault-approle-auth-details",
            contents={0: {"role-id": "role id", "secret-id": "secret id"}},
        )
        state_in = scenario.State(
            leader=True,
            secrets=[approle_secret],
            relations=[peer_relation, pki_relation_provider, pki_relation_requirer],
            config={"common_name": "myhostname.com"},
        )

        self.ctx.run("config_changed", state_in)

        self.mock_vault.sign_pki_certificate_signing_request.assert_called_once_with(
            mount="charm-pki",
            role="charm-pki",
            csr=requirer_csr.csr,
            common_name="subdomain.myhostname.com",
        )
        self.mock_pki_provider_set_relation_certificate.assert_called_once_with(
            relation_id=pki_relation_requirer.relation_id,
            certificate="my certificate",
            ca="my ca",
            certificate_signing_request=requirer_csr.csr,
            chain=["my ca"],
        )

    # Test Auto unseal

    def test_given_autounseal_details_available_when_configure_then_transit_stanza_generated(
        self,
    ):
        pass

    def test_given_outstanding_autounseal_requests_when_configure_then_credentials_are_set(
        self,
    ):
        pass

    # KV

    def test_given_outstanding_kv_request_when_configure_then_kv_relation_data_is_set(
        self,
    ):
        pass

    def test_given_related_kv_client_unit_egress_is_updated_when_configure_then_secret_content_is_updated(
        self,
    ):
        pass
