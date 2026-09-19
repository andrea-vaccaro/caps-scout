#!/usr/bin/env python3
# Part of caps-scout (https://github.com/andrea-vaccaro/caps-scout) - License: GNU General Public License v3

"""WATO rule for the caps-scout agent-plugin bakery rule (`../bakery/caps_scout.py`)."""

from collections.abc import Mapping

from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    CascadingSingleChoice,
    CascadingSingleChoiceElement,
    DefaultValue,
    DictElement,
    Dictionary,
    FixedValue,
    TimeMagnitude,
    TimeSpan,
)
from cmk.rulesets.v1.rule_specs import AgentConfig, Topic


def migrate(value: object) -> Mapping[str, object]:
    if isinstance(value, dict) and "deployment" in value:
        return value
    if isinstance(value, dict) and "deploy" in value:
        return {"deployment": ("sync", None) if value["deploy"] else ("do_not_deploy", None)}
    if value is None:
        return {"deployment": ("do_not_deploy", None)}
    return {"deployment": ("sync", None)}


def _form_spec_agent_config_caps_scout() -> Dictionary:
    return Dictionary(
        help_text=Help(
            "This deploys caps-scout's agent plug-in: it detects which capabilities are"
            " present on the host - database engines, web/app servers, container and"
            " virtualization engines, and more (see the top-level README for the full"
            " list) - and reports them as <tt>caps/*</tt> host labels. The plug-in takes"
            " no configuration of its own; it decides what to report purely from what"
            " it finds on the host - the choice below only controls how the agent runs"
            " it."
        ),
        elements={
            "deployment": DictElement(
                required=True,
                parameter_form=CascadingSingleChoice(
                    title=Title("Deployment type"),
                    elements=(
                        CascadingSingleChoiceElement(
                            name="sync",
                            title=Title("Deploy caps-scout and run it synchronously"),
                            parameter_form=FixedValue(value=None),
                        ),
                        CascadingSingleChoiceElement(
                            name="cached",
                            title=Title("Deploy caps-scout and run it asynchronously"),
                            parameter_form=TimeSpan(
                                displayed_magnitudes=(
                                    TimeMagnitude.HOUR,
                                    TimeMagnitude.MINUTE,
                                )
                            ),
                        ),
                        CascadingSingleChoiceElement(
                            name="do_not_deploy",
                            title=Title("Do not deploy caps-scout"),
                            parameter_form=FixedValue(value=None),
                        ),
                    ),
                    prefill=DefaultValue("sync"),
                ),
            ),
        },
        migrate=migrate,
    )


rule_spec_caps_scout = AgentConfig(
    title=Title("caps-scout (capability discovery)"),
    name="caps_scout",
    topic=Topic.GENERAL,
    parameter_form=_form_spec_agent_config_caps_scout,
)
