#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import time
from pathlib import Path
from typing import List

import yaml
from juju.unit import Unit
from pytest_operator.plugin import OpsTest

# Vault status codes, see
# https://developer.hashicorp.com/vault/api-docs/system/health for more details
METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
APP_NAME = METADATA["name"]
VAULT_STATUS_ACTIVE = 200
VAULT_STATUS_UNSEALED_AND_STANDBY = 429
VAULT_STATUS_NOT_INITIALIZED = 501
VAULT_STATUS_SEALED = 503


async def get_leader_unit(model, application_name: str) -> Unit:
    """Return the leader unit for the given application."""
    for unit in model.units.values():
        if unit.application == application_name and await unit.is_leader_from_status():
            return unit
    raise RuntimeError(f"Leader unit for `{application_name}` not found.")


async def get_unit_status_messages(
    ops_test: OpsTest, app_name: str = APP_NAME
) -> List[tuple[str, str]]:
    """Get the status messages from all the units of the given application.

    Returns:
        A list of tuples with the unit name in the first entry, and the status
        message in the second
    """
    return_code, stdout, stderr = await ops_test.juju("status", "--format", "yaml", app_name)
    if return_code:
        raise RuntimeError(stderr)
    output = yaml.safe_load(stdout)
    unit_statuses = output["applications"][app_name]["units"]
    return [
        (unit_name, unit_status["workload-status"].get("message", ""))
        for (unit_name, unit_status) in unit_statuses.items()
    ]


async def wait_for_status_message(
    ops_test: OpsTest,
    expected_message: str,
    app_name: str = APP_NAME,
    count: int = 1,
    timeout: int = 100,
    cadence: int = 2,
) -> None:
    """Wait for the correct status messages to appear.

    Args:
        ops_test: Ops test Framework.
        app_name: Application name of the Vault, defaults to "vault-k8s"
        count: How many units are expected to be emitting the message
        expected_message: The message that vault units should be setting as a status message
        timeout: Wait time, in seconds, before giving up
        cadence: How often to check the status of the units

    Raises:
        TimeoutError: If the expected amount of statuses weren't found in the given timeout.
    """
    seen = 0
    unit_statuses = []
    while timeout > 0:
        unit_statuses = await get_unit_status_messages(ops_test, app_name=app_name)
        seen = 0
        for unit_name, unit_status_message in unit_statuses:
            if unit_status_message == expected_message:
                seen += 1

        if seen == count:
            return
        time.sleep(cadence)
        timeout -= cadence

    raise TimeoutError(
        f"`{app_name}` didn't show the expected status: `{expected_message}`. Last statuses: {unit_statuses}"
    )
