#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import os

import pytest


def pytest_addoption(parser):
    parser.addoption("--vault_charm_path", action="store", default=None, help="Path to the Vault charm")
    parser.addoption("--kv_requirer_charm_path", action="store", default=None, help="Path to the KV requirer charm")

def pytest_configure(config):
    vault_charm_path = config.getoption("--vault_charm_path")
    kv_requirer_charm_path = config.getoption("--kv_requirer_charm_path")
    if not vault_charm_path:
        pytest.exit("The --vault_charm_path option is required. Tests aborted.")
    if not kv_requirer_charm_path:
        pytest.exit("The --kv_requirer_charm_path option is required. Tests aborted.")
    if not os.path.exists(vault_charm_path):
        pytest.exit(f"The path specified does not exist: {vault_charm_path}")
    if not os.path.exists(kv_requirer_charm_path):
        pytest.exit(f"The path specified does not exist: {kv_requirer_charm_path}")
