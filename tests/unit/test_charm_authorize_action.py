#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import scenario
from ops.testing import ActionFailed
import pytest
from charms.vault_k8s.v0.vault_client import AuditDeviceType

from tests.unit.fixtures import VaultCharmFixtures


class TestCharmAuthorizeAction(VaultCharmFixtures):
    def test_given_unit_not_leader_when_authorize_cham_action_then_fails(self):
        state_in = scenario.State(
            leader=False,
        )

        with pytest.raises(ActionFailed) as e:
            self.ctx.run(self.ctx.on.action("authorize-charm"), state_in)
        assert e.value.message == "This action can only be run by the leader unit"

    def test_given_secret_id_not_found_when_authorize_charm_then_fails(self):
        state_in = scenario.State(
            leader=True,
        )

        with pytest.raises(ActionFailed) as e:
            self.ctx.run(self.ctx.on.action("authorize-charm", params={"secret-id": "my secret id"}), state_in)
        assert e.value.message == "The secret id provided could not be found by the charm. Please grant the token secret to the charm."

    def test_given_api_address_unavailable_when_authorize_charm_then_fails(self):
        self.mock_vault.configure_mock(
            **{
                "authenticate.return_value": False,
            },
        )
        approle_secret = scenario.Secret(
            label="vault-approle-auth-details",
            tracked_content={"role-id": "role id", "secret-id": "secret id"},
        )
        state_in = scenario.State(
            leader=True,
            secrets=[approle_secret],
            networks={
                scenario.Network(
                    "vault-peers",
                    bind_addresses=[scenario.BindAddress([scenario.Address("")])],
                )
            },
        )

        with pytest.raises(ActionFailed) as e:
            self.ctx.run(self.ctx.on.action("authorize-charm", params={"secret-id": approle_secret.id}), state_in)
        assert e.value.message == "API address is not available."

    def test_given_ca_certificate_unavailable_when_authorize_charm_then_fails(self):
        self.mock_tls.configure_mock(
            **{
                "tls_file_available_in_charm.return_value": False,
            },
        )
        approle_secret = scenario.Secret(
            label="vault-approle-auth-details",
            tracked_content={"role-id": "role id", "secret-id": "secret id"},
        )
        peer_relation = scenario.PeerRelation(
            endpoint="vault-peers",
        )
        state_in = scenario.State(
            leader=True,
            secrets=[approle_secret],
            relations=[peer_relation],
            networks={
                scenario.Network(
                    "vault-peers",
                    bind_addresses=[scenario.BindAddress([scenario.Address("1.2.1.2")])],
                )
            },
        )

        with pytest.raises(ActionFailed) as e:
            self.ctx.run(self.ctx.on.action("authorize-charm", params={"secret-id": approle_secret.id}), state_in)
        assert e.value.message == "CA certificate is not available in the charm. Something is wrong."

    def test_given_when_authorize_charm_then_charm_is_authorized(self):
        self.mock_vault.configure_mock(
            **{
                "authenticate.return_value": True,
                "configure_approle.return_value": "my-role-id",
                "generate_role_secret_id.return_value": "my-secret-id",
            },
        )
        user_provided_secret = scenario.Secret(
            tracked_content={"token": "my token"},
        )
        peer_relation = scenario.PeerRelation(
            endpoint="vault-peers",
        )
        state_in = scenario.State(
            leader=True,
            secrets=[user_provided_secret],
            relations=[peer_relation],
            networks={
                scenario.Network(
                    "vault-peers",
                    bind_addresses=[scenario.BindAddress([scenario.Address("1.2.1.2")])],
                )
            },
        )
        out_state = self.ctx.run(self.ctx.on.action("authorize-charm", params={"secret-id": user_provided_secret.id}), state_in)

        self.mock_vault.enable_audit_device.assert_called_once_with(
            device_type=AuditDeviceType.FILE, path="stdout"
        )
        self.mock_vault.enable_approle_auth_method.assert_called_once()
        self.mock_vault.configure_policy.assert_called_once_with(
            policy_name="charm-access",
            policy_path="src/templates/charm_policy.hcl",
        )
        self.mock_vault.configure_approle.assert_called_once_with(
            role_name="charm",
            policies=["charm-access", "default"],
            token_ttl="1h",
            token_max_ttl="1h",
        )
        assert self.ctx.action_results == {
            "result": "Charm authorized successfully. You may now remove the secret."
        }
        assert out_state.get_secret(label="vault-approle-auth-details").tracked_content == {
            "role-id": "my-role-id",
            "secret-id": "my-secret-id",
        }
