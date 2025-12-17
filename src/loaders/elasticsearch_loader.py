# src/loaders/elasticsearch_loader.py
"""
Elasticsearch Loader - Load forensic data into Elasticsearch.

Features:
- Create indices with proper mappings
- Bulk data loading
- Support for all artifact types
"""

import os
import json
from typing import List, Dict, Any, Optional
from datetime import datetime

try:
    from elasticsearch import Elasticsearch
    from elasticsearch.helpers import bulk
    ES_AVAILABLE = True
except ImportError:
    ES_AVAILABLE = False


class ElasticsearchLoader:
    """
    Data loader for Elasticsearch.

    Usage:
        loader = ElasticsearchLoader("http://localhost:9200")
        loader.load_records("forensic-prefetch", records, case_id="case_001")
    """

    # Index mappings for each artifact type
    INDEX_MAPPINGS = {
        "forensic-prefetch": {
            "mappings": {
                "properties": {
                    "artifact_type": {"type": "keyword"},
                    "timestamp": {"type": "date", "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd'T'HH:mm:ss||epoch_millis||strict_date_optional_time"},
                    "executable_name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "prefetch_hash": {"type": "keyword"},
                    "source_file": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "run_count": {"type": "integer"},
                    "files_loaded": {"type": "text"},
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
            }
        },
        "forensic-eventlog": {
            "mappings": {
                "properties": {
                    "artifact_type": {"type": "keyword"},
                    "timestamp": {"type": "date", "format": "yyyy-MM-dd HH:mm:ss.SSSSSSS||yyyy-MM-dd HH:mm:ss||yyyy-MM-dd'T'HH:mm:ss||epoch_millis||strict_date_optional_time"},
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
            }
        },
        "forensic-registry": {
            "mappings": {
                "properties": {
                    "artifact_type": {"type": "keyword"},
                    "timestamp": {"type": "date", "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd'T'HH:mm:ss||epoch_millis||strict_date_optional_time"},
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
            }
        },
        "forensic-browser": {
            "mappings": {
                "properties": {
                    "artifact_type": {"type": "keyword"},
                    "timestamp": {"type": "date", "format": "yyyy-MM-dd'T'HH:mm:ss'Z'||yyyy-MM-dd HH:mm:ss||epoch_millis||strict_date_optional_time"},
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
            }
        },
        "forensic-lnk": {
            "mappings": {
                "properties": {
                    "artifact_type": {"type": "keyword"},
                    "timestamp": {"type": "date", "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd'T'HH:mm:ss||epoch_millis||strict_date_optional_time"},
                    "lnk_name": {"type": "keyword"},
                    "target_path": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "target_extension": {"type": "keyword"},
                    "working_directory": {"type": "text"},
                    "arguments": {"type": "text"},
                    "target_created": {"type": "date", "format": "yyyy-MM-dd HH:mm:ss||strict_date_optional_time", "ignore_malformed": True},
                    "target_modified": {"type": "date", "format": "yyyy-MM-dd HH:mm:ss||strict_date_optional_time", "ignore_malformed": True},
                    "target_accessed": {"type": "date", "format": "yyyy-MM-dd HH:mm:ss||strict_date_optional_time", "ignore_malformed": True},
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
    }

    def __init__(self, es_url: str = "http://localhost:9200",
                 username: str = None, password: str = None,
                 api_key: str = None, verify_certs: bool = True):
        """
        Initialize Elasticsearch connection.

        Args:
            es_url: Elasticsearch URL (e.g., http://localhost:9200)
            username: Username (optional)
            password: Password (optional)
            api_key: API key (optional)
            verify_certs: Verify SSL certificates
        """
        if not ES_AVAILABLE:
            raise ImportError("elasticsearch package not installed. Run: pip install elasticsearch")

        self.es_url = es_url

        # Configure authentication
        es_config = {
            "hosts": [es_url],
            "verify_certs": verify_certs,
        }

        if api_key:
            es_config["api_key"] = api_key
        elif username and password:
            es_config["basic_auth"] = (username, password)

        self.es = Elasticsearch(**es_config)

        # Check connection
        if not self.es.ping():
            raise ConnectionError(f"Cannot connect to Elasticsearch at {es_url}")

        print(f"[ElasticsearchLoader] Connected to {es_url}")

    def create_index(self, index_name: str, force: bool = False) -> bool:
        """
        Create index with proper mapping.

        Args:
            index_name: Index name (e.g., forensic-prefetch)
            force: Delete and recreate if exists

        Returns:
            True if successful
        """
        # Check if index exists
        if self.es.indices.exists(index=index_name):
            if force:
                print(f"[ElasticsearchLoader] Deleting existing index: {index_name}")
                self.es.indices.delete(index=index_name)
            else:
                print(f"[ElasticsearchLoader] Index already exists: {index_name}")
                return True

        # Get mapping
        mapping = self.INDEX_MAPPINGS.get(index_name, {})

        # Create index
        self.es.indices.create(index=index_name, body=mapping)
        print(f"[ElasticsearchLoader] Created index: {index_name}")

        return True

    def load_records(self, index_name: str, records: List[Dict[str, Any]],
                     case_id: str = None, batch_size: int = 1000) -> int:
        """
        Load records into Elasticsearch.

        Args:
            index_name: Index name
            records: List of records to load
            case_id: Case ID for filtering
            batch_size: Batch size for bulk loading

        Returns:
            Number of loaded records
        """
        if not records:
            print(f"[ElasticsearchLoader] No records to load")
            return 0

        # Create index if not exists
        self.create_index(index_name)

        # Prepare documents for bulk
        def generate_actions():
            for record in records:
                doc = record.copy()

                # Add case_id if specified
                if case_id and "_meta" in doc:
                    doc["_meta"]["case_id"] = case_id

                yield {
                    "_index": index_name,
                    "_source": doc
                }

        # Load via bulk
        success, failed = bulk(
            self.es,
            generate_actions(),
            chunk_size=batch_size,
            raise_on_error=False
        )

        if failed:
            print(f"[ElasticsearchLoader] Failed to load {len(failed)} records")
            # Show first errors
            for error in failed[:3]:
                print(f"  Error: {error}")

        print(f"[ElasticsearchLoader] Loaded {success} records into {index_name}")
        return success

    def load_json_file(self, json_file: str, index_name: str, case_id: str = None) -> int:
        """
        Load data from JSON file into Elasticsearch.

        Args:
            json_file: Path to JSON file
            index_name: Index name
            case_id: Case ID

        Returns:
            Number of loaded records
        """
        if not os.path.exists(json_file):
            print(f"[ElasticsearchLoader] File not found: {json_file}")
            return 0

        with open(json_file, 'r', encoding='utf-8') as f:
            records = json.load(f)

        return self.load_records(index_name, records, case_id)

    def search(self, index_name: str, query: Dict = None,
               case_id: str = None, size: int = 100) -> List[Dict]:
        """
        Search in index.

        Args:
            index_name: Index name
            query: Elasticsearch query
            case_id: Filter by case_id
            size: Number of results

        Returns:
            List of found documents
        """
        if query is None:
            query = {"match_all": {}}

        # Add case_id filter
        if case_id:
            query = {
                "bool": {
                    "must": [query],
                    "filter": [{"term": {"_meta.case_id": case_id}}]
                }
            }

        result = self.es.search(
            index=index_name,
            query=query,
            size=size
        )

        return [hit["_source"] for hit in result["hits"]["hits"]]

    def get_stats(self, index_name: str, case_id: str = None) -> Dict:
        """
        Get index statistics.

        Returns:
            Statistics (document count, size, etc.)
        """
        # Total count
        if case_id:
            count_query = {"term": {"_meta.case_id": case_id}}
        else:
            count_query = {"match_all": {}}

        count = self.es.count(index=index_name, query=count_query)

        return {
            "index": index_name,
            "count": count["count"],
            "case_id": case_id
        }

    def delete_case(self, case_id: str, indices: List[str] = None) -> Dict:
        """
        Delete all case data.

        Args:
            case_id: Case ID to delete
            indices: List of indices (default: all forensic-*)

        Returns:
            Deletion statistics
        """
        if indices is None:
            indices = list(self.INDEX_MAPPINGS.keys())

        deleted = {}
        for index in indices:
            try:
                result = self.es.delete_by_query(
                    index=index,
                    query={"term": {"_meta.case_id": case_id}}
                )
                deleted[index] = result.get("deleted", 0)
            except Exception as e:
                deleted[index] = f"Error: {e}"

        return deleted


# Convenience function for quick loading
def load_to_elasticsearch(json_file: str, es_url: str = "http://localhost:9200",
                          index_name: str = None, case_id: str = None) -> int:
    """
    Quick load JSON file into Elasticsearch.

    Args:
        json_file: Path to JSON file
        es_url: Elasticsearch URL
        index_name: Index name (auto-detect from data if not specified)
        case_id: Case ID

    Returns:
        Number of loaded records
    """
    loader = ElasticsearchLoader(es_url)

    # Auto-detect index
    if not index_name:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if data and isinstance(data, list):
                artifact_type = data[0].get("artifact_type", "unknown")
                index_name = f"forensic-{artifact_type}"

    return loader.load_json_file(json_file, index_name, case_id)
