# src/llm/groq_analyzer.py
"""
Groq Analyzer - LLM-powered forensic analysis with Tool Use (FREE)
Uses Groq API with Llama 3.1 70B
"""

import os
import json
import requests
from typing import Dict, List, Any
from datetime import datetime

from groq import Groq
from dotenv import load_dotenv

load_dotenv()


class GroqAnalyzer:
    """
    Forensic analyzer using Groq API with Llama 3.1.
    FREE tier with rate limits.

    Available tools:
    - search_artifacts: Search across all forensic data
    - get_timeline: Get chronological events
    - analyze_program_execution: Analyze specific program runs
    - analyze_web_activity: Analyze browser history
    - find_suspicious_activity: Find anomalies and IOCs
    - get_case_stats: Get statistics about available data
    """

    SYSTEM_PROMPT = """You are an expert digital forensics analyst with access to tools for investigating Windows disk images.

Available data sources:
- Prefetch files: Program execution history (what ran, when, how many times)
- Event logs: Windows system/security events (logins, errors, service installs)
- Registry: System configuration, user activity, autoruns
- Browser history: Web browsing activity
- LNK files: Shortcuts showing recently accessed files

Investigation approach:
1. First use get_case_stats to understand what data is available
2. Use search_artifacts for specific queries (program names, URLs, keywords)
3. Use get_timeline to see chronological sequence of events
4. Use find_suspicious_activity to identify potential IOCs
5. Use analyze_program_execution for deep dive into specific programs
6. Use analyze_web_activity for browser investigation

IMPORTANT: Always call tools when you need data. Do not make assumptions.
Be precise with timestamps and file paths. Identify patterns and anomalies.
Explain your findings clearly and professionally."""

    # Tool definitions in OpenAI format (Groq uses same format)
    TOOLS = [
        {
            "type": "function",
            "function": {
                "name": "search_artifacts",
                "description": "Search across all forensic artifacts (prefetch, eventlog, registry, browser, lnk). Use for finding specific programs, files, URLs, or keywords.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query (program name, URL, keyword, etc.)"
                        },
                        "artifact_type": {
                            "type": "string",
                            "enum": ["prefetch", "eventlog", "registry", "browser", "lnk", "all"],
                            "description": "Type of artifact to search (default: all)"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum results (default: 20)"
                        }
                    },
                    "required": ["query"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "get_timeline",
                "description": "Get chronological timeline of events. Useful for reconstructing what happened and when.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "start_time": {
                            "type": "string",
                            "description": "Start of time range (ISO format: 2023-09-22T00:00:00)"
                        },
                        "end_time": {
                            "type": "string",
                            "description": "End of time range (ISO format: 2023-09-22T23:59:59)"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum events (default: 30)"
                        }
                    }
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "analyze_program_execution",
                "description": "Deep analysis of a specific program's execution history from Prefetch and LNK files.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "program_name": {
                            "type": "string",
                            "description": "Program name to analyze (e.g., chrome.exe, cmd.exe, powershell.exe)"
                        }
                    },
                    "required": ["program_name"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "analyze_web_activity",
                "description": "Analyze browser history. Shows visited sites, domains, and browsing patterns.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Filter by domain (optional)"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum results (default: 30)"
                        }
                    }
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "find_suspicious_activity",
                "description": "Find potentially suspicious activity: executions from TEMP folders, suspicious Event IDs (4625, 4648, 7045, 1102), unusual patterns.",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "get_case_stats",
                "description": "Get statistics about available forensic data: record counts by type, time ranges.",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            }
        }
    ]

    def __init__(self, es_url: str = "http://localhost:9200"):
        self.api_key = os.getenv("GROQ_API_KEY")
        if not self.api_key:
            raise ValueError("GROQ_API_KEY not found in environment. Get free key at https://console.groq.com")

        self.client = Groq(api_key=self.api_key)
        self.es_url = es_url
        self.model = "llama-3.3-70b-versatile"  # Best for tool use
        self.conversation_history: List[Dict] = []
        self.max_history_messages = 10

    def _trim_history(self):
        """Keep only last N messages to reduce token usage"""
        if len(self.conversation_history) > self.max_history_messages:
            self.conversation_history = self.conversation_history[-self.max_history_messages:]

    # ==================== TOOL IMPLEMENTATIONS ====================

    def _es_search(self, index: str, query: str = None, size: int = 50) -> List[Dict]:
        """Execute Elasticsearch search"""
        try:
            body = {
                "size": size,
                "sort": [{"timestamp": {"order": "desc", "unmapped_type": "date"}}]
            }

            if query:
                body["query"] = {
                    "multi_match": {
                        "query": query,
                        "fields": ["*"],
                        "type": "best_fields"
                    }
                }

            response = requests.post(
                f"{self.es_url}/{index}/_search",
                json=body,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                hits = data.get("hits", {}).get("hits", [])
                return [hit["_source"] for hit in hits]
        except Exception as e:
            print(f"[ES Error] {e}")
        return []

    def _tool_search_artifacts(self, query: str, artifact_type: str = "all", limit: int = 20) -> Dict:
        """Search across forensic artifacts"""
        if artifact_type == "all":
            index = "forensic-*"
        else:
            index = f"forensic-{artifact_type}"

        results = self._es_search(index, query, limit)

        simplified = []
        for r in results[:limit]:
            simplified.append({
                "type": r.get("artifact_type", "unknown"),
                "timestamp": r.get("timestamp", ""),
                "summary": self._summarize_record(r)
            })

        return {
            "query": query,
            "artifact_type": artifact_type,
            "total_found": len(results),
            "results": simplified
        }

    def _tool_get_timeline(self, start_time: str = None, end_time: str = None, limit: int = 30) -> Dict:
        """Get timeline of events"""
        body = {
            "size": limit,
            "sort": [{"timestamp": {"order": "asc", "unmapped_type": "date"}}]
        }

        if start_time or end_time:
            time_range = {}
            if start_time:
                time_range["gte"] = start_time
            if end_time:
                time_range["lte"] = end_time
            body["query"] = {"range": {"timestamp": time_range}}

        try:
            response = requests.post(
                f"{self.es_url}/forensic-*/_search",
                json=body,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                hits = data.get("hits", {}).get("hits", [])

                timeline = []
                for hit in hits:
                    r = hit["_source"]
                    timeline.append({
                        "timestamp": r.get("timestamp", ""),
                        "type": r.get("artifact_type", ""),
                        "event": self._summarize_record(r)
                    })

                return {
                    "time_range": {"start": start_time, "end": end_time},
                    "total_events": len(timeline),
                    "timeline": timeline
                }
        except Exception as e:
            return {"error": str(e)}

        return {"timeline": [], "total_events": 0}

    def _tool_analyze_program(self, program_name: str) -> Dict:
        """Analyze program execution"""
        prefetch = self._es_search("forensic-prefetch", program_name, 50)
        lnk = self._es_search("forensic-lnk", program_name, 30)

        executions = []
        for r in prefetch:
            executions.append({
                "time": r.get("timestamp", ""),
                "source": "prefetch",
                "executable": r.get("executable_name", ""),
                "run_count": r.get("run_count", 0)
            })

        for r in lnk:
            executions.append({
                "time": r.get("timestamp", ""),
                "source": "lnk",
                "target": r.get("target_path", "")
            })

        executions.sort(key=lambda x: x.get("time", ""))

        return {
            "program": program_name,
            "prefetch_records": len(prefetch),
            "lnk_records": len(lnk),
            "first_seen": executions[0]["time"] if executions else None,
            "last_seen": executions[-1]["time"] if executions else None,
            "execution_history": executions[:20]
        }

    def _tool_analyze_web(self, domain: str = None, limit: int = 30) -> Dict:
        """Analyze web activity"""
        results = self._es_search("forensic-browser", domain, limit)

        domains = {}
        for r in results:
            d = r.get("domain", "unknown")
            if d not in domains:
                domains[d] = {"count": 0, "visits": []}
            domains[d]["count"] += r.get("visit_count", 1)
            domains[d]["visits"].append({
                "url": r.get("url", "")[:100],
                "title": r.get("title", "")[:50],
                "time": r.get("timestamp", "")
            })

        top = sorted(domains.items(), key=lambda x: x[1]["count"], reverse=True)[:15]

        return {
            "total_records": len(results),
            "unique_domains": len(domains),
            "top_domains": [{"domain": d, "visits": v["count"]} for d, v in top],
            "recent_visits": [
                {"url": r.get("url", "")[:80], "title": r.get("title", "")[:40], "time": r.get("timestamp", "")}
                for r in results[:15]
            ]
        }

    def _tool_find_suspicious(self) -> Dict:
        """Find suspicious activity"""
        suspicious = []

        # Executions from TEMP/Downloads
        temp_exec = self._es_search("forensic-prefetch", "TEMP OR Downloads OR AppData\\Local\\Temp", 30)
        for r in temp_exec:
            exe = r.get("executable_name", "")
            if "temp" in exe.lower() or "download" in exe.lower():
                suspicious.append({
                    "type": "temp_execution",
                    "severity": "medium",
                    "description": f"Program executed from temp folder: {exe}",
                    "timestamp": r.get("timestamp", "")
                })

        # Suspicious Event IDs
        for event_id in [4625, 4648, 7045, 1102]:
            events = self._es_search("forensic-eventlog", str(event_id), 15)
            for r in events:
                if r.get("event_id") == event_id:
                    severity = "high" if event_id in [7045, 1102] else "medium"
                    descriptions = {
                        4625: "Failed login attempt",
                        4648: "Explicit credentials used",
                        7045: "Service installed",
                        1102: "Audit log cleared"
                    }
                    suspicious.append({
                        "type": "suspicious_event",
                        "severity": severity,
                        "description": f"Event {event_id}: {descriptions.get(event_id, '')}",
                        "timestamp": r.get("timestamp", ""),
                        "provider": r.get("provider", "")
                    })

        severity_order = {"high": 0, "medium": 1, "low": 2}
        suspicious.sort(key=lambda x: severity_order.get(x["severity"], 99))

        return {
            "total_suspicious": len(suspicious),
            "by_severity": {
                "high": len([s for s in suspicious if s["severity"] == "high"]),
                "medium": len([s for s in suspicious if s["severity"] == "medium"]),
                "low": len([s for s in suspicious if s["severity"] == "low"])
            },
            "findings": suspicious[:30]
        }

    def _tool_get_stats(self) -> Dict:
        """Get case statistics"""
        stats = {}
        total = 0

        indices = ["forensic-prefetch", "forensic-eventlog", "forensic-registry", "forensic-browser", "forensic-lnk"]

        for index in indices:
            try:
                response = requests.get(f"{self.es_url}/{index}/_count", timeout=5)
                if response.status_code == 200:
                    count = response.json().get("count", 0)
                    stats[index.replace("forensic-", "")] = count
                    total += count
                else:
                    stats[index.replace("forensic-", "")] = 0
            except:
                stats[index.replace("forensic-", "")] = 0

        return {
            "total_records": total,
            "by_artifact_type": stats,
            "elasticsearch_status": "online" if total > 0 else "no data"
        }

    def _summarize_record(self, record: Dict) -> str:
        """Create short summary of a record"""
        art_type = record.get("artifact_type", "")

        if art_type == "prefetch":
            exe = record.get("executable_name", "Unknown")
            if "\\" in exe:
                exe = exe.split("\\")[-1]
            return f"Executed: {exe} (run count: {record.get('run_count', 0)})"

        elif art_type == "eventlog":
            return f"Event {record.get('event_id', '')} - {record.get('provider', '')} [{record.get('level', '')}]"

        elif art_type == "registry":
            return f"{record.get('hive_type', '')}: {record.get('key_path', '')[:60]}..."

        elif art_type == "browser_history":
            return f"{record.get('browser', 'Browser')}: {record.get('title', '')[:40]} | {record.get('domain', '')}"

        elif art_type == "lnk":
            return f"Shortcut: {record.get('lnk_name', '')} -> {record.get('target_path', '')[:50]}"

        return str(record)[:100]

    def _execute_tool(self, tool_name: str, tool_args: Dict) -> str:
        """Execute a tool and return JSON result"""
        try:
            if tool_name == "search_artifacts":
                result = self._tool_search_artifacts(
                    query=tool_args.get("query", ""),
                    artifact_type=tool_args.get("artifact_type", "all"),
                    limit=tool_args.get("limit", 20)
                )
            elif tool_name == "get_timeline":
                result = self._tool_get_timeline(
                    start_time=tool_args.get("start_time"),
                    end_time=tool_args.get("end_time"),
                    limit=tool_args.get("limit", 30)
                )
            elif tool_name == "analyze_program_execution":
                result = self._tool_analyze_program(
                    program_name=tool_args.get("program_name", "")
                )
            elif tool_name == "analyze_web_activity":
                result = self._tool_analyze_web(
                    domain=tool_args.get("domain"),
                    limit=tool_args.get("limit", 30)
                )
            elif tool_name == "find_suspicious_activity":
                result = self._tool_find_suspicious()
            elif tool_name == "get_case_stats":
                result = self._tool_get_stats()
            else:
                result = {"error": f"Unknown tool: {tool_name}"}

            return json.dumps(result, ensure_ascii=False, default=str)

        except Exception as e:
            return json.dumps({"error": str(e)})

    # ==================== MAIN ANALYZE METHOD ====================

    def analyze(self, query: str, case_id: str = None) -> str:
        """
        Analyze forensic data based on user query.
        Groq/Llama will decide which tools to use.
        """
        self._trim_history()

        # Add user message
        self.conversation_history.append({
            "role": "user",
            "content": query
        })

        try:
            # Build messages with system prompt
            messages = [{"role": "system", "content": self.SYSTEM_PROMPT}] + self.conversation_history

            # Initial request with tools
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                tools=self.TOOLS,
                tool_choice="auto",
                max_tokens=4096
            )

            message = response.choices[0].message

            # Handle tool calls loop
            while message.tool_calls:
                # Add assistant message with tool calls
                self.conversation_history.append({
                    "role": "assistant",
                    "content": message.content,
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments
                            }
                        }
                        for tc in message.tool_calls
                    ]
                })

                # Execute tools and add results
                for tool_call in message.tool_calls:
                    tool_name = tool_call.function.name
                    tool_args = json.loads(tool_call.function.arguments)

                    print(f"[Tool] Executing: {tool_name}")
                    result = self._execute_tool(tool_name, tool_args)

                    self.conversation_history.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": result
                    })

                # Continue conversation
                messages = [{"role": "system", "content": self.SYSTEM_PROMPT}] + self.conversation_history
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    tools=self.TOOLS,
                    tool_choice="auto",
                    max_tokens=4096
                )
                message = response.choices[0].message

            # Get final response
            final_text = message.content or ""

            # Add to history
            self.conversation_history.append({
                "role": "assistant",
                "content": final_text
            })

            return final_text

        except Exception as e:
            error_msg = str(e)
            if "rate_limit" in error_msg.lower():
                return "Rate limit reached. Please wait a moment and try again. (Groq free tier limit)"
            return f"Error: {error_msg}"

    def clear_history(self):
        """Clear conversation history"""
        self.conversation_history = []


# CLI interface
if __name__ == "__main__":
    import sys

    print("=" * 50)
    print("Groq Forensic Analyzer (FREE - Llama 3.1 70B)")
    print("=" * 50)

    try:
        analyzer = GroqAnalyzer()
        print("[OK] Connected to Groq API")
    except ValueError as e:
        print(f"[ERROR] {e}")
        print("\nGet your free API key at: https://console.groq.com")
        sys.exit(1)

    print("\nCommands:")
    print("  /clear - Clear conversation")
    print("  /quit - Exit")
    print("\nAsk any question about the forensic data.\n")

    while True:
        try:
            query = input("You: ").strip()

            if not query:
                continue

            if query == "/quit":
                break
            elif query == "/clear":
                analyzer.clear_history()
                print("\n[Conversation cleared]\n")
                continue

            print("\nAnalyzing...\n")
            response = analyzer.analyze(query)

            print(response)
            print()

        except KeyboardInterrupt:
            print("\n\nExiting...")
            break
