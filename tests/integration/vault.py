#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Vault helper functions."""

import logging
import time
from os.path import abspath
from typing import Optional, Tuple

import hvac

logger = logging.getLogger(__name__)

# Vault status codes, see
# https://developer.hashicorp.com/vault/api-docs/system/health for more details
VAULT_STATUS_ACTIVE = 200
VAULT_STATUS_NOT_INITIALIZED = 501


class Vault:
    def __init__(self, url: str, ca_file_location: str, token: Optional[str] = None):
        self.url = url
        self.client = hvac.Client(url=self.url, verify=abspath(ca_file_location))
        if token:
            self.client.token = token

    def initialize(self) -> Tuple[str, str]:
        """Initialize the vault unit and return the root token and unseal key."""
        initialize_response = self.client.sys.initialize(secret_shares=1, secret_threshold=1)
        root_token, unseal_key = initialize_response["root_token"], initialize_response["keys"][0]
        return root_token, unseal_key

    def is_initialized(self) -> bool:
        """Check if the vault unit is initialized."""
        response = self.client.sys.read_health_status()
        return response.status_code != VAULT_STATUS_NOT_INITIALIZED

    def is_sealed(self) -> bool:
        """Check if the vault unit is sealed."""
        return self.client.sys.is_sealed()

    def is_active(self) -> bool:
        """Check if the vault unit is active."""
        response = self.client.sys.read_health_status()
        return response.status_code == VAULT_STATUS_ACTIVE

    def wait_for_node_to_be_unsealed(self) -> None:
        """Wait for the vault unit to be unsealed.

        Args:
            endpoint (str): The endpoint of the vault unit
            ca_file_location (str): The path to the CA file
        """
        timeout = 300
        t0 = time.time()
        while time.time() < t0 + timeout:
            time.sleep(5)
            if not self.is_sealed():
                logger.info("Vault unit is unsealed.")
                return
        raise TimeoutError("Timed out waiting for vault to be unsealed.")

    def unseal(self, unseal_key: str) -> None:
        """Unseal a vault unit.

        Args:
            endpoint (str): The endpoint of the vault unit
            ca_file_location (str): The path to the CA file
            unseal_key (str): The unseal key
        """
        if not self.client.sys.is_sealed():
            return
        self.client.sys.submit_unseal_key(unseal_key)
        logger.info("Unsealed vault unit: %s.", self.url)

    def wait_for_raft_nodes(self, expected_num_nodes: int) -> None:
        """Wait for the specified number of units to join the raft cluster.

        Args:
            endpoint (str): The endpoint of the Vault unit
            token (str): The root token
            ca_file_location (str): The path to the CA file
            expected_num_nodes (int): The number of units to wait for
        """
        timeout = 300
        t0 = time.time()
        while time.time() < t0 + timeout:
            time.sleep(5)
            response = self.client.sys.read_raft_config()
            servers = response["data"]["config"]["servers"]
            current_num_voters = sum(1 for server in servers if server.get("voter", False))
            current_num_nodes = len(servers)
            if  current_num_nodes != expected_num_nodes:
                logger.info(f"Nodes in the raft cluster: {current_num_nodes}/{expected_num_nodes}")
                continue
            if current_num_voters != expected_num_nodes:
                logger.info(f"Voters in the raft cluster: {current_num_voters}/{expected_num_nodes}")
                continue
            logger.info(f"Expected number of nodes are part of the raft cluster: {current_num_nodes}/{expected_num_nodes}")
            return
        raise TimeoutError("Timed out waiting for nodes to be part of the raft cluster.")
