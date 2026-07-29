"""Disabled authentication probe descriptor."""

from __future__ import annotations


class ModuleNotApproved(Exception):
    """A module cannot run under the scanner's active policy."""


class DisabledAuthModule:
    module_id = "AUTHN-001"
    enabled = False

    def run(self, context: object) -> None:
        raise ModuleNotApproved("module is not approved")
