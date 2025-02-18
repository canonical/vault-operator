#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import ops.testing as testing
import pytest

from tests.unit.fixtures import VaultCharmFixtures


class TestCharmGetIngressUrlAction(VaultCharmFixtures):
    def test_given_ingress_relation_created_and_url_ready_when_get_ingress_url_action_then_url_is_returned(
        self,
    ):
        state_in = testing.State(
            relations=[
                testing.Relation(
                    endpoint="ingress",
                    remote_app_name="haproxy",
                    remote_app_data={"ingress": '{"url": "https://haproxy/debug-vault/"}'},
                )
            ],
        )
        self.ctx.run(self.ctx.on.action("get-ingress-url"), state_in)
        assert self.ctx.action_results == {"ingress-url": "https://haproxy/debug-vault/"}

    def test_given_ingress_url_not_ready_when_get_ingress_url_action_then_url_is_not_returned(
        self,
    ):
        state_in = testing.State(
            relations=[
                testing.Relation(
                    endpoint="ingress",
                    interface="ingress",
                    remote_app_name="haproxy",
                )
            ],
        )
        with pytest.raises(testing.ActionFailed) as e:
            self.ctx.run(self.ctx.on.action("get-ingress-url"), state_in)
        assert e.value.message == "Ingress URL is not available yet"

    def test_given_ingress_relation_not_created_when_get_ingress_url_action_then_url_is_not_returned(
        self,
    ):
        state_in = testing.State(
            relations=[],
        )
        with pytest.raises(testing.ActionFailed) as e:
            self.ctx.run(self.ctx.on.action("get-ingress-url"), state_in)
        assert e.value.message == "Ingress relation does not exist"
