#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


from unittest.mock import MagicMock, call

import scenario

from tests.unit.fixtures import VaultCharmFixtures


class TestCharmRemove(VaultCharmFixtures):
    def test_given_can_connect_when_remove_then_node_removed_from_raft_cluster_and_service_is_stopped(
        self,
    ):
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": True,
                "is_sealed.return_value": False,
                "is_node_in_raft_peers.return_value": True,
                "get_num_raft_peers.return_value": 4,
            },
        )
        model_name = "model-name"
        approle_secret = scenario.Secret(
            id="0",
            label="vault-approle-auth-details",
            contents={0: {"role-id": "role id", "secret-id": "secret id"}},
        )
        peer_relation = scenario.PeerRelation(
            endpoint="vault-peers",
        )
        state_in = scenario.State(
            secrets=[approle_secret],
            model=scenario.Model(name=model_name),
            relations=[peer_relation],
        )

        self.ctx.run("remove", state_in)

        self.mock_vault.remove_raft_node.assert_called_with(id=f"{model_name}-vault/0")
        self.mock_machine.remove_path.assert_has_calls(
            calls=[
                call(path="/var/snap/vault/common/raft/vault.db"),
                call(path="/var/snap/vault/common/raft/raft/raft.db"),
            ]
        )

    def test_given_vault_service_active_when_remove_then_service_is_stopped(
        self,
    ):
        self.mock_machine.get_service.return_value = MagicMock(
            is_running=MagicMock(
                return_value=True,
            ),
        )
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": True,
                "is_sealed.return_value": False,
                "is_node_in_raft_peers.return_value": True,
                "get_num_raft_peers.return_value": 4,
            },
        )
        model_name = "model-name"
        approle_secret = scenario.Secret(
            id="0",
            label="vault-approle-auth-details",
            contents={0: {"role-id": "role id", "secret-id": "secret id"}},
        )
        peer_relation = scenario.PeerRelation(
            endpoint="vault-peers",
        )
        state_in = scenario.State(
            secrets=[approle_secret],
            model=scenario.Model(name=model_name),
            relations=[peer_relation],
        )

        self.ctx.run("remove", state_in)

        self.mock_machine.stop.assert_has_calls([call("vault")])
