"""Application message templates with unmodified dynamic evidence parameters."""
from __future__ import annotations


class Message(str):
    """A canonical string that also retains the template needed for localization.

    Keeping a string subclass preserves JSON and existing finding comparisons.
    The explicit reduction retains metadata across dataclasses.asdict/deepcopy.
    """

    def __new__(cls, template: str, parameters: dict | None = None):
        parameters = dict(parameters or {})
        value = super().__new__(cls, template.format(**parameters) if parameters else template)
        value.template = template
        value.parameters = parameters
        return value

    def __reduce_ex__(self, protocol):
        return type(self), (self.template, self.parameters)


def msg(template: str, **parameters) -> Message:
    return Message(template, parameters)
