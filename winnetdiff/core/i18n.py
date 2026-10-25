"""Explicit, dependency-free catalogs. Raw operating-system evidence is not translated."""
from __future__ import annotations
import contextvars
import functools
from winnetdiff.core.config import normalize_language
from winnetdiff.core.catalog import DIAGNOSTIC_TRANSLATIONS, SIMPLIFIED_CHARACTERS
from winnetdiff.gui.catalog import TRANSLATIONS
from winnetdiff.core.scenario_catalog import SCENARIO_TRANSLATIONS
from winnetdiff.core.messages import Message, msg
from winnetdiff.core.extension_catalog import EXTENSION_TRANSLATIONS

_LANGUAGE = contextvars.ContextVar('winnetdiff_language', default='en')


def set_language(locale: str) -> str:
    value = normalize_language(locale)
    _LANGUAGE.set(value)
    return value


def get_language() -> str:
    return _LANGUAGE.get()


@functools.lru_cache(maxsize=8192)
def _translate(value: str, language: str) -> str:
    catalogs = {**DIAGNOSTIC_TRANSLATIONS, **TRANSLATIONS, **SCENARIO_TRANSLATIONS, **EXTENSION_TRANSLATIONS}
    if value in catalogs and catalogs[value].get(language):
        return catalogs[value][language]
    # Unknown values may be user names, paths or operating-system evidence.
    # Never translate their substrings or convert their individual characters.
    return value


def tr(text: object, locale: str | None = None, **kwargs) -> str:
    language = normalize_language(locale or get_language())
    if isinstance(text, BaseException) and text.args and isinstance(text.args[0], Message):
        text = text.args[0]
    if isinstance(text, Message):
        template = _translate(text.template, language)
        parameters = {key: tr(value, language) if isinstance(value, Message) else value
                      for key, value in text.parameters.items()}
        parameters.update(kwargs)
        return template.format(**parameters) if parameters else template
    value = _translate(str(text), language)
    return value.format(**kwargs) if kwargs else value


def localized_data(data, locale: str | None = None, _explanatory: bool = False):
    """Translate explanatory values, leaving identifiers and command/raw evidence intact."""
    if isinstance(data, list):
        return [localized_data(item, locale, _explanatory) for item in data]
    if isinstance(data, dict):
        # These fields are authored prose. All other string fields are identities
        # or raw data, even when a value happens to equal a short catalog key.
        explanatory = {'title', 'reasoning', 'interpretation', 'grade_definition',
                       'alternatives', 'verification', 'conditions', 'limitations',
                       'severity', 'confidence', 'layer', 'status_title',
                       'Reasons', 'Severity', 'Confidence', 'reason', 'execution', 'note'}
        raw = {'evidence', 'raw_evidence', 'Sources', 'command', 'commands',
               'Path', 'PathName', 'raw_columns', 'error'}
        return {key: value if key in raw else localized_data(value, locale, key in explanatory)
                if key in explanatory or isinstance(value, (dict, list)) else value
                for key, value in data.items()}
    return tr(data, locale) if isinstance(data, str) and _explanatory else data
