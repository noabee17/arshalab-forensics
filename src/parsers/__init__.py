# src/parsers/__init__.py
"""
Forensic Artifact Parsers
=========================

Единый модуль парсеров для Windows артефактов.
Все парсеры находятся в parsers.py и наследуют BaseParser.

Naming Convention: {Artifact}_{Tool}_Parser
- Prefetch_PECmd_Parser
- EventLog_EvtxECmd_Parser
- Registry_RECmd_Parser
- Browser_SQLite_Parser
- LNK_LECmd_Parser

Чтобы добавить новый парсер:
1. Создайте класс в parsers.py, наследующий BaseParser
2. Реализуйте: name, description, index_name, _parse_impl, _normalize_record
3. Добавьте в PARSERS dict ниже
"""

from .base import BaseParser
from .parsers import (
    # Новые имена с названием парсера
    Prefetch_PECmd_Parser,
    EventLog_EvtxECmd_Parser,
    Registry_RECmd_Parser,
    Browser_SQLite_Parser,
    LNK_LECmd_Parser,
    # Старые имена (алиасы для обратной совместимости)
    PrefetchParser,
    EventLogParser,
    RegistryParser,
    BrowserHistoryParser,
    LnkParser,
)

# Реестр парсеров по типу артефакта
PARSERS = {
    "prefetch": Prefetch_PECmd_Parser,
    "eventlog": EventLog_EvtxECmd_Parser,
    "registry": Registry_RECmd_Parser,
    "browser": Browser_SQLite_Parser,
    "lnk": LNK_LECmd_Parser,
}

__all__ = [
    # Base class
    "BaseParser",
    # New names (recommended)
    "Prefetch_PECmd_Parser",
    "EventLog_EvtxECmd_Parser",
    "Registry_RECmd_Parser",
    "Browser_SQLite_Parser",
    "LNK_LECmd_Parser",
    # Legacy aliases
    "PrefetchParser",
    "EventLogParser",
    "RegistryParser",
    "BrowserHistoryParser",
    "LnkParser",
    # Registry
    "PARSERS",
]
