# src/llm/llm_orchestrator.py
import yaml
import json
from anthropic import Anthropic
from pathlib import Path
import os

class LLMOrchestrator:
    """
    LLM с доступом к базе знаний для принятия решений
    """
    
    def __init__(self, knowledge_base_path: str = "config/llm_knowledge.yaml"):
        # API ключ из переменной окружения
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise Exception("ANTHROPIC_API_KEY not found. Set it in .env file")
        
        self.client = Anthropic(api_key=api_key)
        
        # Загружаем базу знаний
        with open(knowledge_base_path, 'r', encoding='utf-8') as f:
            self.knowledge = yaml.safe_load(f)
        
        # Загружаем конфигурацию артефактов
        with open("config/artifacts.yaml", 'r', encoding='utf-8') as f:
            self.artifacts_config = yaml.safe_load(f)
    
    def analyze_query(self, user_query: str) -> dict:
        """
        LLM анализирует запрос, используя базу знаний
        """
        
        prompt = self._build_analysis_prompt(user_query)
        
        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            messages=[{
                "role": "user",
                "content": prompt
            }]
        )
        
        # Парсим JSON ответ
        result = json.loads(response.content[0].text)
        return result
    
    def _build_analysis_prompt(self, user_query: str) -> str:
        """
        Строим промпт с инжекцией базы знаний
        """
        
        prompt = f"""You are a digital forensics expert analyzing an investigation query.

# Your Knowledge Base

## Available Artifacts
{self._format_artifacts_info()}

## Investigation Types
{self._format_investigation_types()}

# User Query
"{user_query}"

# Your Task
Analyze the query and return a JSON response with this structure:

{{
  "investigation_type": "program_execution|web_activity|timeline_reconstruction",
  "artifacts_needed": ["artifact1", "artifact2"],
  "priority_order": ["most_important_artifact"],
  "time_constraints": {{
    "date": "YYYY-MM-DD or null",
    "start_time": "HH:MM:SS or null",
    "end_time": "HH:MM:SS or null"
  }},
  "keywords": ["keyword1"],
  "analysis_strategy": "Brief description"
}}

Return ONLY valid JSON, no markdown.
"""
        return prompt
    
    def _format_artifacts_info(self) -> str:
        """Форматируем информацию об артефактах"""
        lines = []
        for name, config in self.artifacts_config['artifacts'].items():
            lines.append(f"### {name}")
            lines.append(f"Description: {config['description']}")
            lines.append(f"Capabilities: {', '.join(config['capabilities'])}")
            lines.append("")
        return "\n".join(lines)
    
    def _format_investigation_types(self) -> str:
        """Форматируем типы расследований"""
        lines = []
        for inv_type, config in self.knowledge['forensic_knowledge']['investigation_types'].items():
            lines.append(f"### {inv_type}")
            lines.append(f"Description: {config['description']}")
            lines.append(f"Primary artifacts: {', '.join(config['primary_artifacts'])}")
            lines.append("")
        return "\n".join(lines)
    
    def generate_report(self, timeline: list, correlations: list, anomalies: list, query: str) -> str:
        """
        Генерирует финальный отчёт
        """
        
        summary_data = {
            "total_events": len(timeline),
            "time_range": f"{timeline[0]['timestamp']} to {timeline[-1]['timestamp']}" if timeline else "N/A",
            "anomalies": anomalies,
            "top_events": timeline[:20]
        }
        
        prompt = f"""Generate a forensic analysis report.

Original Query: {query}

Analysis Data:
{json.dumps(summary_data, indent=2, default=str)}

Generate a professional report with:
1. Executive Summary
2. Timeline (top 10 events)
3. Key Findings
4. Anomalies (if any)

Be concise and professional.
"""
        
        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4000,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return response.content[0].text