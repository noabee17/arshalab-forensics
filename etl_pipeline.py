# etl_pipeline.py
"""
ETL Pipeline: Extract → Transform → Load

Полный цикл обработки форензик образов:
1. Extract: TSK извлекает файлы из образа
2. Transform: Парсеры преобразуют в JSON
3. Load: Загрузка в Elasticsearch (основное) или SQLite (fallback)
"""

import os
import json
import glob
from datetime import datetime
import yaml


class ETLPipeline:
    """
    ETL Pipeline для форензик анализа.

    Поддерживает загрузку в:
    - Elasticsearch (основной режим)
    - SQLite (fallback если ES недоступен)
    """

    # Маппинг artifact_type -> index_name
    INDEX_NAMES = {
        "prefetch": "forensic-prefetch",
        "eventlog": "forensic-eventlog",
        "registry": "forensic-registry",
        "browser": "forensic-browser",
        "lnk": "forensic-lnk",
    }

    def __init__(self, image_path: str, output_dir: str, artifacts: list,
                 es_url: str = None, es_username: str = None, es_password: str = None,
                 use_sqlite: bool = False):
        """
        Args:
            image_path: Путь к образу диска (E01, RAW, etc)
            output_dir: Директория для выходных файлов
            artifacts: Список артефактов для обработки
            es_url: URL Elasticsearch (опционально, по умолчанию http://localhost:9200)
            es_username: Username для ES (опционально)
            es_password: Password для ES (опционально)
            use_sqlite: Использовать SQLite вместо ES (для тестирования)
        """
        self.image_path = image_path
        self.output_dir = output_dir
        self.artifacts = artifacts
        self.case_id = f"case_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        # Elasticsearch настройки
        self.es_url = es_url or os.getenv("ES_URL", "http://localhost:9200")
        self.es_username = es_username or os.getenv("ES_USERNAME")
        self.es_password = es_password or os.getenv("ES_PASSWORD")
        self.use_sqlite = use_sqlite

        # Загружаем конфигурацию
        config_path = os.path.join(os.path.dirname(__file__), "config/artifacts.yaml")
        with open(config_path, encoding='utf-8') as f:
            self.config = yaml.safe_load(f)

        # Создаём директории
        self.raw_dir = os.path.join(output_dir, "raw")
        self.parsed_dir = os.path.join(output_dir, "parsed")

        os.makedirs(self.raw_dir, exist_ok=True)
        os.makedirs(self.parsed_dir, exist_ok=True)

        # Инициализация хранилища
        self.es_loader = None
        self.db_path = None

        if use_sqlite:
            self._init_sqlite()
        else:
            self._init_elasticsearch()

    def _init_elasticsearch(self):
        """Инициализирует подключение к Elasticsearch."""
        try:
            from src.loaders import ElasticsearchLoader

            self.es_loader = ElasticsearchLoader(
                es_url=self.es_url,
                username=self.es_username,
                password=self.es_password
            )
            print(f"[OK] Connected to Elasticsearch: {self.es_url}")

        except Exception as e:
            print(f"[!] Elasticsearch not available: {e}")
            print(f"[!] Falling back to SQLite")
            self.use_sqlite = True
            self._init_sqlite()

    def _init_sqlite(self):
        """Инициализирует SQLite базу данных."""
        import sqlite3

        self.db_path = os.path.join(self.output_dir, f"{self.case_id}.db")

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Читаем SQL схему
        schema_path = os.path.join(os.path.dirname(__file__), "database_schema.sql")
        with open(schema_path, 'r', encoding='utf-8') as f:
            schema = f.read()

        cursor.executescript(schema)

        # Добавляем запись о кейсе
        cursor.execute("""
            INSERT INTO cases (case_id, image_path, created_at, status)
            VALUES (?, ?, ?, ?)
        """, (self.case_id, self.image_path, datetime.now(), 'processing'))

        conn.commit()
        conn.close()

        print(f"[OK] SQLite database initialized: {self.db_path}")

    def run(self, status_callback=None):
        """
        Запускает полный ETL процесс.

        Args:
            status_callback: функция для обновления статуса (для GUI)
        """
        def log(msg):
            """Логирует в консоль и через callback."""
            # Sanitize for Windows console (cp1252)
            try:
                safe_msg = str(msg).encode('cp1252', errors='replace').decode('cp1252')
                print(safe_msg)
            except:
                print(str(msg).encode('ascii', errors='replace').decode('ascii'))
            if status_callback:
                status_callback(str(msg))

        storage_type = "SQLite" if self.use_sqlite else "Elasticsearch"

        log(f"ETL Pipeline Started")
        log(f"Case ID: {self.case_id}")
        log(f"Image: {self.image_path}")
        log(f"Artifacts: {', '.join(self.artifacts)}")
        log(f"Storage: {storage_type}")

        for artifact_type in self.artifacts:
            try:
                log(f"--- Processing: {artifact_type} ---")

                # 1. Extract
                log(f"Step 1: Extracting {artifact_type}...")
                extracted_files = self._extract_artifact(artifact_type, log)

                if not extracted_files:
                    log(f"[!] No files extracted for {artifact_type}")
                    continue

                log(f"[OK] Extracted {len(extracted_files)} files")

                # 2. Transform (Parse)
                log(f"Step 2: Parsing {artifact_type}...")
                parsed_json = self._parse_artifact(artifact_type, log)

                if not parsed_json:
                    log(f"[!] Parsing failed for {artifact_type}")
                    continue

                log(f"[OK] Parsed successfully")

                # 3. Load
                log(f"Step 3: Loading into {storage_type}...")
                self._load_data(artifact_type, parsed_json, log)

                log(f"[OK] Loaded to {storage_type}")

            except Exception as e:
                log(f"[X] Error processing {artifact_type}: {e}")
                import traceback
                traceback.print_exc()

        # Финализация
        self._finalize()

        log(f"ETL Pipeline Completed!")
        log(f"Case ID: {self.case_id}")

    def _extract_artifact(self, artifact_type: str, log=None) -> list:
        """Извлекает артефакты через TSK."""
        if log is None:
            log = print

        if artifact_type not in self.config['artifacts']:
            return []

        artifact_config = self.config['artifacts'][artifact_type]
        paths = artifact_config['paths']

        output_artifact_dir = os.path.join(self.raw_dir, artifact_type)
        os.makedirs(output_artifact_dir, exist_ok=True)

        from src.collectors.tsk_collector import TSKCollector

        collector = TSKCollector(self.image_path)
        extracted = collector.extract_files(paths, output_artifact_dir, log_callback=log)

        return extracted

    def _parse_artifact(self, artifact_type: str, log=None) -> str:
        """Парсит артефакты через унифицированную архитектуру парсеров."""
        if log is None:
            log = print

        from src.parsers import PARSERS

        if artifact_type not in PARSERS:
            log(f"  [!] No parser registered for: {artifact_type}")
            return None

        artifact_config = self.config['artifacts'][artifact_type]
        # Используем абсолютные пути
        input_dir = os.path.abspath(os.path.join(self.raw_dir, artifact_type))
        output_dir = os.path.abspath(os.path.join(self.parsed_dir, artifact_type))

        os.makedirs(output_dir, exist_ok=True)

        # Проверяем наличие файлов
        input_files = glob.glob(os.path.join(input_dir, "*"))
        if not input_files:
            return None

        log(f"  Found {len(input_files)} files to parse")

        # Создаём парсер
        ParserClass = PARSERS[artifact_type]
        executable_path = artifact_config['parser_config'].get('executable')

        parser = ParserClass(
            executable_path=executable_path,
            output_dir=output_dir
        )

        # Парсим и сохраняем в JSON
        json_output = parser.parse_to_json(input_dir, self.case_id)
        return json_output

    def _load_data(self, artifact_type: str, json_file: str, log=None):
        """Загружает данные в хранилище."""
        if log is None:
            log = print

        if self.use_sqlite:
            self._load_to_sqlite(artifact_type, json_file, log)
        else:
            self._load_to_elasticsearch(artifact_type, json_file, log)

    def _load_to_elasticsearch(self, artifact_type: str, json_file: str, log=None):
        """Загружает JSON в Elasticsearch."""
        if log is None:
            log = print

        index_name = self.INDEX_NAMES.get(artifact_type, f"forensic-{artifact_type}")

        with open(json_file, 'r', encoding='utf-8') as f:
            records = json.load(f)

        log(f"  Loading {len(records)} records into {index_name}...")

        loaded = self.es_loader.load_records(
            index_name=index_name,
            records=records,
            case_id=self.case_id
        )

        log(f"  Loaded {loaded} records into {index_name}")

    def _load_to_sqlite(self, artifact_type: str, json_file: str, log=None):
        """Загружает JSON в SQLite (fallback)."""
        if log is None:
            log = print
        import sqlite3

        with open(json_file, 'r', encoding='utf-8') as f:
            records = json.load(f)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        if artifact_type == "prefetch":
            for record in records:
                cursor.execute("""
                    INSERT INTO prefetch (case_id, executable_name, run_time,
                                         prefetch_hash, file_path, files_loaded, volume_info)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    self.case_id,
                    record.get('executable_name', ''),
                    record.get('timestamp', ''),
                    record.get('prefetch_hash', ''),
                    record.get('source_file', ''),
                    json.dumps(record.get('files_loaded', [])),
                    record.get('volume_info', '')
                ))

        elif artifact_type == "eventlog":
            for record in records:
                cursor.execute("""
                    INSERT INTO eventlog (case_id, event_id, timestamp, source,
                                         level, computer_name, user_name, message)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    self.case_id,
                    record.get('event_id', 0),
                    record.get('timestamp', ''),
                    record.get('provider', ''),
                    record.get('level', ''),
                    record.get('computer_name', ''),
                    record.get('user_id', ''),
                    record.get('message', '')
                ))

        elif artifact_type == "registry":
            for record in records:
                cursor.execute("""
                    INSERT INTO registry (case_id, hive_type, key_path, value_name,
                                         value_data, value_type, last_modified)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    self.case_id,
                    record.get('hive_type', ''),
                    record.get('key_path', ''),
                    record.get('value_name', ''),
                    record.get('value_data', ''),
                    record.get('value_type', ''),
                    record.get('timestamp', '')
                ))

        elif artifact_type == "browser":
            for record in records:
                cursor.execute("""
                    INSERT INTO browser_history (case_id, browser, url, title,
                                                visit_time, visit_count, typed_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    self.case_id,
                    record.get('browser', ''),
                    record.get('url', ''),
                    record.get('title', ''),
                    record.get('timestamp', ''),
                    record.get('visit_count', 0),
                    record.get('typed_count', 0)
                ))

        elif artifact_type == "lnk":
            for record in records:
                cursor.execute("""
                    INSERT INTO lnk_files (case_id, lnk_name, target_path,
                                          working_directory, arguments,
                                          creation_time, access_time, modified_time)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    self.case_id,
                    record.get('lnk_name', ''),
                    record.get('target_path', ''),
                    record.get('working_directory', ''),
                    record.get('arguments', ''),
                    record.get('source_created', ''),
                    record.get('source_accessed', ''),
                    record.get('source_modified', '')
                ))

        conn.commit()
        conn.close()

        print(f"  Loaded {len(records)} records into {artifact_type} table")

    def _finalize(self):
        """Финализирует обработку."""
        if self.use_sqlite:
            import sqlite3
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE cases SET status = 'completed' WHERE case_id = ?
            """, (self.case_id,))
            conn.commit()
            conn.close()


if __name__ == "__main__":
    # Тестовый запуск с SQLite (fallback)
    pipeline = ETLPipeline(
        image_path="images/test.E01",
        output_dir="output/test_pipeline",
        artifacts=["prefetch"],
        use_sqlite=True  # Для тестирования без ES
    )

    pipeline.run()
