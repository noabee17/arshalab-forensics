# src/elastic/client.py
"""
Elasticsearch Client - клиент для работы с Elasticsearch.

Функционал:
- Создание индексов с правильными маппингами
- Bulk-загрузка данных из парсеров
- Поиск и агрегации
- Управление кейсами
"""

import json
from typing import List, Dict, Any, Optional
from datetime import datetime

try:
    from elasticsearch import Elasticsearch
    from elasticsearch.helpers import bulk
except ImportError:
    raise ImportError("elasticsearch package required. Install: pip install elasticsearch")


class ElasticClient:
    """
    Клиент для работы с Elasticsearch.

    Usage:
        client = ElasticClient("http://localhost:9200")
        client.index_records("forensic-prefetch", records)
        results = client.search("forensic-prefetch", "calc.exe")
    """

    # Маппинги для каждого типа артефактов
    INDEX_MAPPINGS = {
        "forensic-prefetch": {
            "properties": {
                "artifact_type": {"type": "keyword"},
                "timestamp": {"type": "date", "ignore_malformed": True},
                "executable_name": {"type": "keyword"},
                "prefetch_hash": {"type": "keyword"},
                "source_file": {"type": "text"},
                "run_count": {"type": "integer"},
                "files_loaded": {"type": "keyword"},
                "volume_info": {"type": "text"},
                "_meta": {
                    "properties": {
                        "parser": {"type": "keyword"},
                        "case_id": {"type": "keyword"},
                        "parsed_at": {"type": "date"},
                        "source_path": {"type": "text"}
                    }
                }
            }
        },
        "forensic-eventlog": {
            "properties": {
                "artifact_type": {"type": "keyword"},
                "timestamp": {"type": "date", "ignore_malformed": True},
                "event_id": {"type": "integer"},
                "provider": {"type": "keyword"},
                "channel": {"type": "keyword"},
                "level": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "computer_name": {"type": "keyword"},
                "user_id": {"type": "keyword"},
                "message": {"type": "text"},
                "record_id": {"type": "long"},
                "_meta": {
                    "properties": {
                        "parser": {"type": "keyword"},
                        "case_id": {"type": "keyword"},
                        "parsed_at": {"type": "date"},
                        "source_path": {"type": "text"}
                    }
                }
            }
        },
        "forensic-registry": {
            "properties": {
                "artifact_type": {"type": "keyword"},
                "timestamp": {"type": "date", "ignore_malformed": True},
                "hive_type": {"type": "keyword"},
                "key_path": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "value_name": {"type": "keyword"},
                "value_data": {"type": "text"},
                "value_type": {"type": "keyword"},
                "category": {"type": "keyword"},
                "description": {"type": "text"},
                "_meta": {
                    "properties": {
                        "parser": {"type": "keyword"},
                        "case_id": {"type": "keyword"},
                        "parsed_at": {"type": "date"},
                        "source_path": {"type": "text"}
                    }
                }
            }
        },
        "forensic-browser": {
            "properties": {
                "artifact_type": {"type": "keyword"},
                "timestamp": {"type": "date", "ignore_malformed": True},
                "browser": {"type": "keyword"},
                "url": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "domain": {"type": "keyword"},
                "title": {"type": "text"},
                "visit_count": {"type": "integer"},
                "typed_count": {"type": "integer"},
                "hidden": {"type": "boolean"},
                "_meta": {
                    "properties": {
                        "parser": {"type": "keyword"},
                        "case_id": {"type": "keyword"},
                        "parsed_at": {"type": "date"},
                        "source_path": {"type": "text"}
                    }
                }
            }
        },
        "forensic-lnk": {
            "properties": {
                "artifact_type": {"type": "keyword"},
                "timestamp": {"type": "date", "ignore_malformed": True},
                "lnk_name": {"type": "keyword"},
                "target_path": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "target_extension": {"type": "keyword"},
                "working_directory": {"type": "text"},
                "arguments": {"type": "text"},
                "target_created": {"type": "date", "ignore_malformed": True},
                "target_modified": {"type": "date", "ignore_malformed": True},
                "target_accessed": {"type": "date", "ignore_malformed": True},
                "source_created": {"type": "date", "ignore_malformed": True},
                "source_modified": {"type": "date", "ignore_malformed": True},
                "source_accessed": {"type": "date", "ignore_malformed": True},
                "file_size": {"type": "long"},
                "drive_type": {"type": "keyword"},
                "volume_label": {"type": "keyword"},
                "volume_serial": {"type": "keyword"},
                "machine_id": {"type": "keyword"},
                "_meta": {
                    "properties": {
                        "parser": {"type": "keyword"},
                        "case_id": {"type": "keyword"},
                        "parsed_at": {"type": "date"},
                        "source_path": {"type": "text"}
                    }
                }
            }
        }
    }

    def __init__(self, host: str = "http://localhost:9200", api_key: str = None):
        """
        Args:
            host: URL Elasticsearch (например: http://localhost:9200)
            api_key: API ключ для аутентификации (опционально)
        """
        self.host = host

        if api_key:
            self.es = Elasticsearch(host, api_key=api_key)
        else:
            self.es = Elasticsearch(host)

        # Проверяем подключение
        if not self.es.ping():
            raise ConnectionError(f"Cannot connect to Elasticsearch at {host}")

        print(f"[Elastic] Connected to {host}")

    def create_index(self, index_name: str, force: bool = False) -> bool:
        """
        Создаёт индекс с правильным маппингом.

        Args:
            index_name: Имя индекса (например: forensic-prefetch)
            force: Удалить существующий индекс

        Returns:
            True если индекс создан
        """
        if self.es.indices.exists(index=index_name):
            if force:
                print(f"[Elastic] Deleting existing index: {index_name}")
                self.es.indices.delete(index=index_name)
            else:
                print(f"[Elastic] Index already exists: {index_name}")
                return True

        # Получаем маппинг
        mapping = self.INDEX_MAPPINGS.get(index_name, {})

        body = {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0
            },
            "mappings": mapping
        }

        self.es.indices.create(index=index_name, body=body)
        print(f"[Elastic] Created index: {index_name}")
        return True

    def index_records(self, index_name: str, records: List[Dict[str, Any]]) -> int:
        """
        Загружает записи в Elasticsearch (bulk).

        Args:
            index_name: Имя индекса
            records: Список записей для загрузки

        Returns:
            Количество загруженных записей
        """
        if not records:
            return 0

        # Создаём индекс если не существует
        self.create_index(index_name)

        # Подготавливаем bulk actions
        actions = []
        for record in records:
            action = {
                "_index": index_name,
                "_source": record
            }
            actions.append(action)

        # Bulk загрузка
        success, errors = bulk(self.es, actions, raise_on_error=False)

        if errors:
            print(f"[Elastic] Bulk errors: {len(errors)}")

        print(f"[Elastic] Indexed {success} records to {index_name}")
        return success

    def search(
        self,
        index_name: str,
        query: str = None,
        filters: Dict[str, Any] = None,
        time_range: Dict[str, str] = None,
        size: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Поиск по индексу.

        Args:
            index_name: Имя индекса или паттерн (forensic-*)
            query: Текстовый запрос
            filters: Фильтры {field: value}
            time_range: {"gte": "2024-01-01", "lte": "2024-12-31"}
            size: Максимум результатов

        Returns:
            Список найденных документов
        """
        must = []

        # Текстовый поиск
        if query:
            must.append({
                "multi_match": {
                    "query": query,
                    "fields": ["*"],
                    "type": "best_fields"
                }
            })

        # Фильтры
        if filters:
            for field, value in filters.items():
                must.append({"term": {field: value}})

        # Временной диапазон
        if time_range:
            must.append({
                "range": {
                    "timestamp": time_range
                }
            })

        # Формируем запрос
        body = {
            "query": {
                "bool": {
                    "must": must if must else [{"match_all": {}}]
                }
            },
            "size": size,
            "sort": [{"timestamp": {"order": "desc", "unmapped_type": "date"}}]
        }

        result = self.es.search(index=index_name, body=body)

        # Извлекаем документы
        hits = result.get("hits", {}).get("hits", [])
        return [hit["_source"] for hit in hits]

    def get_timeline(
        self,
        case_id: str,
        start_time: str = None,
        end_time: str = None,
        size: int = 1000
    ) -> List[Dict[str, Any]]:
        """
        Получает timeline всех событий по кейсу.

        Args:
            case_id: ID кейса
            start_time: Начало периода (ISO format)
            end_time: Конец периода (ISO format)
            size: Максимум событий

        Returns:
            Список событий отсортированных по времени
        """
        must = [{"term": {"_meta.case_id": case_id}}]

        if start_time or end_time:
            time_range = {}
            if start_time:
                time_range["gte"] = start_time
            if end_time:
                time_range["lte"] = end_time
            must.append({"range": {"timestamp": time_range}})

        body = {
            "query": {"bool": {"must": must}},
            "size": size,
            "sort": [{"timestamp": {"order": "asc", "unmapped_type": "date"}}]
        }

        result = self.es.search(index="forensic-*", body=body)
        hits = result.get("hits", {}).get("hits", [])
        return [hit["_source"] for hit in hits]

    def get_stats(self, case_id: str = None) -> Dict[str, Any]:
        """
        Получает статистику по индексам.

        Returns:
            Словарь со статистикой
        """
        stats = {}

        for index_name in self.INDEX_MAPPINGS.keys():
            if not self.es.indices.exists(index=index_name):
                stats[index_name] = {"count": 0}
                continue

            # Считаем документы
            query = {"match_all": {}}
            if case_id:
                query = {"term": {"_meta.case_id": case_id}}

            result = self.es.count(index=index_name, body={"query": query})
            stats[index_name] = {"count": result.get("count", 0)}

        return stats

    def delete_case(self, case_id: str) -> int:
        """
        Удаляет все данные по кейсу.

        Returns:
            Количество удалённых документов
        """
        body = {
            "query": {
                "term": {"_meta.case_id": case_id}
            }
        }

        result = self.es.delete_by_query(index="forensic-*", body=body)
        deleted = result.get("deleted", 0)

        print(f"[Elastic] Deleted {deleted} documents for case {case_id}")
        return deleted
