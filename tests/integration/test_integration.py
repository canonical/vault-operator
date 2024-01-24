#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import logging
from pathlib import Path

import pytest
import yaml
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APP_NAME = METADATA["name"]
GRAFANA_AGENT_APPLICATION_NAME = "grafana-agent"


@pytest.fixture(scope="module")
@pytest.mark.abort_on_fail
async def build_and_deploy(ops_test: OpsTest):
    """Build the charm-under-test and deploy it."""
    assert ops_test.model
    charm = await ops_test.build_charm(".")
    await ops_test.model.deploy(
        charm,
        application_name=APP_NAME,
        trust=True,
    )

    pytest.mark.abort_on_fail
    @pytest.fixture(scope="module")
    async def deploy_grafana_agent(ops_test: OpsTest) -> None:
        """Deploys grafana-agent-operator.

        Args:
            ops_test: Ops test Framework.
        """
        assert ops_test.model
        await ops_test.model.deploy(
            GRAFANA_AGENT_APPLICATION_NAME,
            application_name=GRAFANA_AGENT_APPLICATION_NAME,
            trust=True,
        )

@pytest.mark.abort_on_fail
async def test_given_charm_build_when_deploy_then_status_active(
    ops_test: OpsTest, build_and_deploy
):
    assert ops_test.model
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=1000,
    )


@pytest.mark.abort_on_fail
async def test_given_grafana_agent_deployed_when_relate_to_grafana_agent_then_status_is_active(
    ops_test: OpsTest, build_and_deploy, deploy_grafana_agent
):
    assert ops_test.model
    await ops_test.model.integrate(
        APP_NAME,
        GRAFANA_AGENT_APPLICATION_NAME,
    )
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=1000,
    )
