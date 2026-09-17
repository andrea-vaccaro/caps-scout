#!/usr/bin/env python3
# Part of caps-scout (https://github.com/andrea-vaccaro/caps-scout) - License: GNU General Public License v3

"""WATO rule for the caps-scout agent-plugin bakery rule (`../bakery/caps_scout.py`)."""

from cmk.rulesets.v1 import Help, Label, Title
from cmk.rulesets.v1.form_specs import BooleanChoice, DefaultValue, DictElement, Dictionary
from cmk.rulesets.v1.rule_specs import AgentConfig, Topic


def _form_spec_agent_config_caps_scout() -> Dictionary:
    return Dictionary(
        help_text=Help(
            "This deploys caps-scout's agent plug-in: it detects which capabilities are"
            " present on the host - database engines, web/app servers, container and"
            " virtualization engines, and more (see the top-level README for the full"
            " list) - and reports them as <tt>caps/*</tt> host labels. The plug-in runs"
            " synchronously and takes no configuration of its own; it decides what to"
            " report purely from what it finds on the host."
        ),
        elements={
            "deploy": DictElement(
                required=True,
                parameter_form=BooleanChoice(
                    label=Label("Deploy the caps-scout plug-in"),
                    prefill=DefaultValue(True),
                ),
            ),
        },
    )


rule_spec_caps_scout = AgentConfig(
    title=Title("caps-scout (capability discovery)"),
    name="caps_scout",
    topic=Topic.GENERAL,
    parameter_form=_form_spec_agent_config_caps_scout,
)
