# src/extractor/__init__.py
"""
TSK Collector - извлечение артефактов из образов дисков через The Sleuth Kit.

Основной класс TSKCollector используется в etl_pipeline.py
"""

from ..collectors.tsk_collector import TSKCollector

# Алиас для обратной совместимости
TSKExtractor = TSKCollector

__all__ = ["TSKCollector", "TSKExtractor"]
