# src/elastic/__init__.py
"""
Elasticsearch Integration
=========================

Модуль для работы с Elasticsearch:
- Загрузка данных из парсеров
- Поиск по индексам
- Управление индексами
"""

from .client import ElasticClient

__all__ = ["ElasticClient"]
