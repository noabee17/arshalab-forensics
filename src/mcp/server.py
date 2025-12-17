# src/mcp/server.py
"""
MCP Server - сервер Model Context Protocol для форензик анализа.

Интегрируется с Cursor/Claude и предоставляет инструменты для:
- Поиска по артефактам Windows
- Построения timeline событий
- Анализа активности пользователей
- Корреляции данных из разных источников
"""

import json
import sys
from typing import Any, Dict, List, Optional
from datetime import datetime

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
except ImportError:
    raise ImportError("mcp package required. Install: pip install mcp")

sys.path.insert(0, str(__file__).replace("src/mcp/server.py", ""))
from src.elastic.client import ElasticClient


class ForensicMCPServer:
    """
    MCP Server для форензик анализа.

    Предоставляет инструменты для LLM:
    - search_artifacts: Поиск по всем артефактам
    - get_timeline: Построение хронологии событий
    - analyze_program_execution: Анализ запусков программ
    - analyze_web_activity: Анализ веб-активности
    - get_registry_autoruns: Получение автозапуска
    - get_case_stats: Статистика по кейсу
    """

    def __init__(self, elastic_host: str = "http://localhost:9200"):
        self.server = Server("forensic-analyzer")
        self.elastic = ElasticClient(elastic_host)
        self._setup_tools()

    def _setup_tools(self):
        """Регистрирует инструменты MCP."""

        @self.server.list_tools()
        async def list_tools() -> List[Tool]:
            return [
                Tool(
                    name="search_artifacts",
                    description="""
                    Поиск по форензик артефактам Windows.
                    Ищет по всем типам: prefetch, eventlog, registry, browser, lnk.

                    Примеры запросов:
                    - "calc.exe" - найти запуски калькулятора
                    - "google.com" - найти посещения Google
                    - "Run" - найти записи автозапуска в реестре
                    """,
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Поисковый запрос (имя файла, URL, ключ реестра и т.д.)"
                            },
                            "artifact_type": {
                                "type": "string",
                                "enum": ["prefetch", "eventlog", "registry", "browser", "lnk", "all"],
                                "description": "Тип артефакта для поиска (по умолчанию: all)"
                            },
                            "case_id": {
                                "type": "string",
                                "description": "ID кейса для фильтрации"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Максимум результатов (по умолчанию: 50)"
                            }
                        },
                        "required": ["query"]
                    }
                ),
                Tool(
                    name="get_timeline",
                    description="""
                    Построить хронологию событий за указанный период.
                    Объединяет данные из всех артефактов и сортирует по времени.

                    Полезно для:
                    - Восстановления последовательности действий
                    - Анализа инцидента
                    - Понимания что происходило в определённое время
                    """,
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "case_id": {
                                "type": "string",
                                "description": "ID кейса"
                            },
                            "start_time": {
                                "type": "string",
                                "description": "Начало периода (ISO format: 2024-01-15T10:00:00)"
                            },
                            "end_time": {
                                "type": "string",
                                "description": "Конец периода (ISO format: 2024-01-15T18:00:00)"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Максимум событий (по умолчанию: 100)"
                            }
                        },
                        "required": ["case_id"]
                    }
                ),
                Tool(
                    name="analyze_program_execution",
                    description="""
                    Анализ запусков программы.
                    Показывает когда и сколько раз запускалась программа.

                    Данные из:
                    - Prefetch файлов (точное время запусков)
                    - LNK файлов (ярлыки к программе)
                    """,
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "program_name": {
                                "type": "string",
                                "description": "Имя программы (например: chrome.exe, cmd.exe)"
                            },
                            "case_id": {
                                "type": "string",
                                "description": "ID кейса"
                            }
                        },
                        "required": ["program_name"]
                    }
                ),
                Tool(
                    name="analyze_web_activity",
                    description="""
                    Анализ веб-активности пользователя.

                    Показывает:
                    - Посещённые сайты
                    - Частоту посещений
                    - Временные паттерны
                    """,
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "domain": {
                                "type": "string",
                                "description": "Домен для фильтрации (опционально)"
                            },
                            "case_id": {
                                "type": "string",
                                "description": "ID кейса"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Максимум результатов"
                            }
                        }
                    }
                ),
                Tool(
                    name="get_registry_autoruns",
                    description="""
                    Получить программы из автозапуска Windows.

                    Проверяет ключи:
                    - Run / RunOnce
                    - Services
                    - Scheduled Tasks
                    """,
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "case_id": {
                                "type": "string",
                                "description": "ID кейса"
                            }
                        }
                    }
                ),
                Tool(
                    name="get_case_stats",
                    description="""
                    Получить статистику по кейсу.

                    Показывает:
                    - Количество записей по каждому типу артефактов
                    - Временной диапазон данных
                    - Топ программ/сайтов
                    """,
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "case_id": {
                                "type": "string",
                                "description": "ID кейса (опционально, если не указан - общая статистика)"
                            }
                        }
                    }
                ),
                Tool(
                    name="find_suspicious_activity",
                    description="""
                    Поиск подозрительной активности.

                    Проверяет:
                    - Запуски из TEMP/Downloads
                    - Подозрительные Event ID (4625, 4648, 7045)
                    - Необычные автозапуски
                    - Ночная активность
                    """,
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "case_id": {
                                "type": "string",
                                "description": "ID кейса"
                            }
                        },
                        "required": ["case_id"]
                    }
                ),
            ]

        @self.server.call_tool()
        async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
            try:
                result = await self._handle_tool(name, arguments)
                return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False, default=str))]
            except Exception as e:
                return [TextContent(type="text", text=f"Error: {str(e)}")]

    async def _handle_tool(self, name: str, args: Dict[str, Any]) -> Any:
        """Обработчик вызовов инструментов."""

        if name == "search_artifacts":
            return self._search_artifacts(
                query=args.get("query"),
                artifact_type=args.get("artifact_type", "all"),
                case_id=args.get("case_id"),
                limit=args.get("limit", 50)
            )

        elif name == "get_timeline":
            return self._get_timeline(
                case_id=args.get("case_id"),
                start_time=args.get("start_time"),
                end_time=args.get("end_time"),
                limit=args.get("limit", 100)
            )

        elif name == "analyze_program_execution":
            return self._analyze_program(
                program_name=args.get("program_name"),
                case_id=args.get("case_id")
            )

        elif name == "analyze_web_activity":
            return self._analyze_web(
                domain=args.get("domain"),
                case_id=args.get("case_id"),
                limit=args.get("limit", 100)
            )

        elif name == "get_registry_autoruns":
            return self._get_autoruns(case_id=args.get("case_id"))

        elif name == "get_case_stats":
            return self._get_stats(case_id=args.get("case_id"))

        elif name == "find_suspicious_activity":
            return self._find_suspicious(case_id=args.get("case_id"))

        else:
            raise ValueError(f"Unknown tool: {name}")

    def _search_artifacts(self, query: str, artifact_type: str, case_id: str, limit: int) -> Dict:
        """Поиск по артефактам."""
        index = "forensic-*"
        if artifact_type and artifact_type != "all":
            index = f"forensic-{artifact_type}"

        filters = {}
        if case_id:
            filters["_meta.case_id"] = case_id

        results = self.elastic.search(
            index_name=index,
            query=query,
            filters=filters if filters else None,
            size=limit
        )

        return {
            "query": query,
            "artifact_type": artifact_type,
            "total": len(results),
            "results": results
        }

    def _get_timeline(self, case_id: str, start_time: str, end_time: str, limit: int) -> Dict:
        """Построение timeline."""
        results = self.elastic.get_timeline(
            case_id=case_id,
            start_time=start_time,
            end_time=end_time,
            size=limit
        )

        return {
            "case_id": case_id,
            "time_range": {"start": start_time, "end": end_time},
            "total_events": len(results),
            "timeline": results
        }

    def _analyze_program(self, program_name: str, case_id: str) -> Dict:
        """Анализ запусков программы."""
        # Поиск в Prefetch
        prefetch_results = self.elastic.search(
            index_name="forensic-prefetch",
            query=program_name,
            filters={"_meta.case_id": case_id} if case_id else None,
            size=100
        )

        # Поиск в LNK
        lnk_results = self.elastic.search(
            index_name="forensic-lnk",
            query=program_name,
            filters={"_meta.case_id": case_id} if case_id else None,
            size=100
        )

        # Собираем времена запусков
        execution_times = []
        for r in prefetch_results:
            if r.get("timestamp"):
                execution_times.append({
                    "time": r["timestamp"],
                    "source": "prefetch",
                    "executable": r.get("executable_name", "")
                })

        for r in lnk_results:
            if r.get("timestamp"):
                execution_times.append({
                    "time": r["timestamp"],
                    "source": "lnk",
                    "target": r.get("target_path", "")
                })

        # Сортируем по времени
        execution_times.sort(key=lambda x: x.get("time", ""))

        return {
            "program": program_name,
            "total_executions": len(prefetch_results),
            "related_shortcuts": len(lnk_results),
            "execution_history": execution_times,
            "first_seen": execution_times[0]["time"] if execution_times else None,
            "last_seen": execution_times[-1]["time"] if execution_times else None
        }

    def _analyze_web(self, domain: str, case_id: str, limit: int) -> Dict:
        """Анализ веб-активности."""
        filters = {}
        if case_id:
            filters["_meta.case_id"] = case_id
        if domain:
            filters["domain"] = domain

        results = self.elastic.search(
            index_name="forensic-browser",
            query=domain if domain else None,
            filters=filters if filters else None,
            size=limit
        )

        # Группируем по доменам
        domains = {}
        for r in results:
            d = r.get("domain", "unknown")
            if d not in domains:
                domains[d] = {"count": 0, "visits": []}
            domains[d]["count"] += r.get("visit_count", 1)
            domains[d]["visits"].append({
                "url": r.get("url", ""),
                "title": r.get("title", ""),
                "time": r.get("timestamp", "")
            })

        # Топ доменов
        top_domains = sorted(domains.items(), key=lambda x: x[1]["count"], reverse=True)[:20]

        return {
            "total_records": len(results),
            "unique_domains": len(domains),
            "top_domains": [{"domain": d, "visit_count": v["count"]} for d, v in top_domains],
            "recent_visits": results[:20]
        }

    def _get_autoruns(self, case_id: str) -> Dict:
        """Получение автозапуска из реестра."""
        filters = {"category": "autorun"}
        if case_id:
            filters["_meta.case_id"] = case_id

        results = self.elastic.search(
            index_name="forensic-registry",
            filters=filters,
            size=200
        )

        # Также ищем по ключевым словам
        run_results = self.elastic.search(
            index_name="forensic-registry",
            query="Run OR RunOnce OR Services",
            filters={"_meta.case_id": case_id} if case_id else None,
            size=200
        )

        # Объединяем и убираем дубликаты
        all_results = {r.get("key_path", ""): r for r in results + run_results}

        return {
            "total_autoruns": len(all_results),
            "autoruns": list(all_results.values())
        }

    def _get_stats(self, case_id: str) -> Dict:
        """Статистика по кейсу."""
        stats = self.elastic.get_stats(case_id)

        total = sum(s.get("count", 0) for s in stats.values())

        return {
            "case_id": case_id or "all",
            "total_records": total,
            "by_artifact_type": stats
        }

    def _find_suspicious(self, case_id: str) -> Dict:
        """Поиск подозрительной активности."""
        suspicious = []

        # 1. Запуски из TEMP
        temp_executions = self.elastic.search(
            index_name="forensic-prefetch",
            query="TEMP OR Downloads OR AppData",
            filters={"_meta.case_id": case_id} if case_id else None,
            size=50
        )
        for r in temp_executions:
            suspicious.append({
                "type": "temp_execution",
                "severity": "medium",
                "description": f"Program executed from temp folder: {r.get('executable_name', '')}",
                "timestamp": r.get("timestamp"),
                "details": r
            })

        # 2. Подозрительные Event ID
        suspicious_events = self.elastic.search(
            index_name="forensic-eventlog",
            query="4625 OR 4648 OR 7045 OR 1102",  # Failed login, explicit creds, service install, log cleared
            filters={"_meta.case_id": case_id} if case_id else None,
            size=50
        )
        for r in suspicious_events:
            event_id = r.get("event_id", 0)
            severity = "high" if event_id in [7045, 1102] else "medium"
            suspicious.append({
                "type": "suspicious_event",
                "severity": severity,
                "description": f"Suspicious Event ID {event_id}: {r.get('message', '')[:100]}",
                "timestamp": r.get("timestamp"),
                "details": r
            })

        # Сортируем по severity
        severity_order = {"high": 0, "medium": 1, "low": 2}
        suspicious.sort(key=lambda x: severity_order.get(x["severity"], 99))

        return {
            "case_id": case_id,
            "total_suspicious": len(suspicious),
            "by_severity": {
                "high": len([s for s in suspicious if s["severity"] == "high"]),
                "medium": len([s for s in suspicious if s["severity"] == "medium"]),
                "low": len([s for s in suspicious if s["severity"] == "low"])
            },
            "findings": suspicious
        }

    async def run(self):
        """Запуск MCP сервера."""
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(read_stream, write_stream, self.server.create_initialization_options())


# Entry point
async def main():
    import os
    elastic_host = os.getenv("ELASTICSEARCH_HOST", "http://localhost:9200")
    server = ForensicMCPServer(elastic_host)
    await server.run()


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
