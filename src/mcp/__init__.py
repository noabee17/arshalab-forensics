# src/mcp/__init__.py
"""
MCP Server for Forensic Analysis
================================

Model Context Protocol сервер для интеграции с Cursor/Claude.

Предоставляет инструменты:
- search_artifacts: Поиск по артефактам
- get_timeline: Построение timeline
- analyze_program: Анализ запусков программы
- analyze_user_activity: Анализ активности пользователя
- get_stats: Статистика по кейсу

Также содержит:
- ElasticsearchMCPClient: Клиент для официального Elasticsearch MCP Server
"""

from .server import ForensicMCPServer
from .es_mcp_client import ElasticsearchMCPClient, ElasticsearchMCPClientSync

__all__ = ["ForensicMCPServer", "ElasticsearchMCPClient", "ElasticsearchMCPClientSync"]
