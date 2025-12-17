# src/loaders/__init__.py
"""
Loaders module - загрузка данных в различные хранилища.

Поддерживаемые хранилища:
- Elasticsearch (основное)
- SQLite (локальный бэкап)
"""

from .elasticsearch_loader import ElasticsearchLoader, load_to_elasticsearch
from .sqlite_loader import SQLiteLoader

__all__ = [
    "ElasticsearchLoader",
    "load_to_elasticsearch",
    "SQLiteLoader",
]
