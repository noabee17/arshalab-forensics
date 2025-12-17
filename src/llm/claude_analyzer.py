# src/llm/claude_analyzer.py
"""
Claude Analyzer - LLM-powered forensic analysis with Tool Use
"""

import os
import json
import requests
from typing import Dict, List, Any
from datetime import datetime

import anthropic
from dotenv import load_dotenv

load_dotenv()


class ClaudeAnalyzer:
    """
    Forensic analyzer using Claude with Tool Use.

    Claude decides which tools to call based on user query.
    Available tools:
    - search_artifacts: Search across all forensic data
    - get_timeline: Get chronological events
    - analyze_program_execution: Analyze specific program runs
    - analyze_web_activity: Analyze browser history
    - find_suspicious_activity: Find anomalies and IOCs
    - get_case_stats: Get statistics about available data
    """

    BASE_SYSTEM_PROMPT = """You are ArshaLab forensic analyst. Answer in user's language. Be concise.

RULES:
- Be PROACTIVE: find something suspicious → dig deeper with more tools
- Chain tool calls to build complete picture
- Severity: [CRITICAL] malware/ransomware, [HIGH] temp executions/log clearing, [MEDIUM] failed logins, [LOW] info

OUTPUT FORMAT:
1. **Summary** - 1-2 sentences
2. **Findings** - with severity tags, paths, timestamps
3. **Next Steps** - specific search queries"""

    # Tool definitions for Claude
    TOOLS = [
        {
            "name": "search_artifacts",
            "description": "Search across all forensic artifacts (prefetch, eventlog, registry, browser, lnk). Use for finding specific programs, files, URLs, or keywords.",
            "input_schema": {
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
        },
        {
            "name": "get_timeline",
            "description": "Get chronological timeline of events. Useful for reconstructing what happened and when.",
            "input_schema": {
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
        },
        {
            "name": "analyze_program_execution",
            "description": "Deep analysis of a specific program's execution history from Prefetch and LNK files.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "program_name": {
                        "type": "string",
                        "description": "Program name to analyze (e.g., chrome.exe, cmd.exe, powershell.exe)"
                    }
                },
                "required": ["program_name"]
            }
        },
        {
            "name": "analyze_web_activity",
            "description": "Analyze browser history. Shows visited sites, domains, and browsing patterns.",
            "input_schema": {
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
        },
        {
            "name": "find_suspicious_activity",
            "description": "Find potentially suspicious activity: executions from TEMP folders, suspicious Event IDs (4625, 4648, 7045, 1102), unusual patterns.",
            "input_schema": {
                "type": "object",
                "properties": {}
            }
        },
        {
            "name": "get_case_stats",
            "description": "Get statistics about available forensic data: record counts by type, time ranges.",
            "input_schema": {
                "type": "object",
                "properties": {}
            }
        }
    ]

    def __init__(self, es_url: str = "http://localhost:9200", incident_context: str = None, session_id: str = None):
        self.api_key = os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY not found in environment")

        self.client = anthropic.Anthropic(api_key=self.api_key)
        self.es_url = es_url
        self.model = "claude-3-5-haiku-20241022"
        self.conversation_history: List[Dict] = []
        self.incident_context = incident_context
        self.session_id = session_id or "default"
        self.max_history_messages = 20  # Increased for better context retention

        # Build system prompt with incident context if provided
        self.system_prompt = self._build_system_prompt()

    def _build_system_prompt(self) -> str:
        """Build system prompt with optional incident context"""
        prompt = self.BASE_SYSTEM_PROMPT

        if self.incident_context:
            prompt += f"""

=== INCIDENT BRIEFING ===
The following incident details have been provided. Use this information to focus your investigation:

{self.incident_context}

Focus your analysis on finding evidence related to this incident. Correlate timestamps, look for IOCs mentioned, and prioritize relevant artifacts.
========================="""

        return prompt

    def set_incident_context(self, context: str):
        """Update incident context and rebuild system prompt"""
        self.incident_context = context
        self.system_prompt = self._build_system_prompt()

    def _trim_history(self):
        """Keep only last N messages to reduce token usage.

        Important: Must preserve tool_use/tool_result pairs together.
        If we cut in the middle of a tool exchange, Claude API returns 400 error.
        """
        if len(self.conversation_history) <= self.max_history_messages:
            return

        # Find safe cut point - must be at a "user" message that doesn't contain tool_result
        # Start from the position that would give us max_history_messages
        cut_start = len(self.conversation_history) - self.max_history_messages

        # Scan forward to find a safe cut point (user message with simple text content)
        for i in range(cut_start, len(self.conversation_history)):
            msg = self.conversation_history[i]
            if msg.get("role") == "user":
                content = msg.get("content")
                # Check if it's a simple text message (not tool_result)
                if isinstance(content, str):
                    self.conversation_history = self.conversation_history[i:]
                    return
                # If it's a list, check it's not tool_result
                if isinstance(content, list):
                    is_tool_result = any(
                        isinstance(c, dict) and c.get("type") == "tool_result"
                        for c in content
                    )
                    if not is_tool_result:
                        self.conversation_history = self.conversation_history[i:]
                        return

        # If no safe point found, just clear history to be safe
        self.conversation_history = []

    # ==================== TOOL IMPLEMENTATIONS ====================

    def _es_search(self, index: str, query: str = None, size: int = 50) -> List[Dict]:
        """Execute Elasticsearch search"""
        try:
            body = {"size": size}

            if query:
                body["query"] = {
                    "query_string": {
                        "query": f"*{query}*",
                        "default_operator": "AND",
                        "analyze_wildcard": True
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
            else:
                print(f"[ES Error] Status {response.status_code}: {response.text[:200]}")
        except Exception as e:
            print(f"[ES Error] {e}")
        return []

    def _tool_search_artifacts(self, query: str, artifact_type: str = "all", limit: int = 50) -> Dict:
        """Search across forensic artifacts - returns FULL records for investigation"""
        if artifact_type == "all":
            index = "forensic-*"
        else:
            index = f"forensic-{artifact_type}"

        results = self._es_search(index, query, limit)

        # Return FULL forensic records - investigators need complete data
        detailed_results = []
        for r in results[:limit]:
            art_type = r.get("artifact_type", "unknown")
            record = {
                "artifact_type": art_type,
                "timestamp": r.get("timestamp", ""),
            }

            if art_type == "prefetch":
                record.update({
                    "executable_name": r.get("executable_name", ""),
                    "executable_path": r.get("executable_path", ""),
                    "run_count": r.get("run_count", 0),
                    "prefetch_hash": r.get("prefetch_hash", ""),
                    # Include files_loaded that match query for context
                    "files_loaded": self._filter_matched_files(r.get("files_loaded", []), query),
                    "total_files_loaded": len(r.get("files_loaded", []))
                })

            elif art_type == "eventlog":
                record.update({
                    "event_id": r.get("event_id", ""),
                    "provider": r.get("provider", ""),
                    "level": r.get("level", ""),
                    "computer_name": r.get("computer_name", ""),
                    "user_id": r.get("user_id", ""),
                    "message": r.get("message", "")[:500],  # Truncate very long messages
                })

            elif art_type == "registry":
                record.update({
                    "hive_type": r.get("hive_type", ""),
                    "key_path": r.get("key_path", ""),
                    "value_name": r.get("value_name", ""),
                    "value_data": r.get("value_data", ""),
                    "value_type": r.get("value_type", ""),
                    "category": r.get("category", ""),
                    "description": r.get("description", ""),
                })

            elif art_type == "browser_history":
                record.update({
                    "browser": r.get("browser", ""),
                    "url": r.get("url", ""),
                    "title": r.get("title", ""),
                    "visit_count": r.get("visit_count", 0),
                    "domain": r.get("domain", ""),
                })

            elif art_type == "lnk":
                record.update({
                    "lnk_name": r.get("lnk_name", ""),
                    "target_path": r.get("target_path", ""),
                    "working_directory": r.get("working_directory", ""),
                    "arguments": r.get("arguments", ""),
                    "source_created": r.get("source_created", ""),
                    "source_modified": r.get("source_modified", ""),
                    "source_accessed": r.get("source_accessed", ""),
                })

            detailed_results.append(record)

        return {
            "query": query,
            "artifact_type": artifact_type,
            "total_found": len(results),
            "results": detailed_results
        }

    def _filter_matched_files(self, files: list, query: str) -> list:
        """Filter files_loaded to show matches + limit for context"""
        if not query or not files:
            return files[:20]  # Return first 20 if no query

        query_lower = query.lower()
        matched = [f for f in files if query_lower in f.lower()]

        if matched:
            return matched[:50]  # All matches up to 50
        return files[:20]  # No matches, show first 20

    def _tool_get_timeline(self, start_time: str = None, end_time: str = None, limit: int = 100) -> Dict:
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
        """Analyze program execution - returns FULL data for investigation"""
        # Search prefetch
        prefetch = self._es_search("forensic-prefetch", program_name, 100)
        # Search LNK
        lnk = self._es_search("forensic-lnk", program_name, 50)
        # Search registry for persistence/installation
        registry = self._es_search("forensic-registry", program_name, 50)

        # Full prefetch records
        prefetch_details = []
        for r in prefetch:
            prefetch_details.append({
                "timestamp": r.get("timestamp", ""),
                "executable_name": r.get("executable_name", ""),
                "executable_path": r.get("executable_path", ""),
                "run_count": r.get("run_count", 0),
                "prefetch_hash": r.get("prefetch_hash", ""),
                "files_loaded": self._filter_matched_files(r.get("files_loaded", []), program_name),
                "total_files_loaded": len(r.get("files_loaded", []))
            })

        # Full LNK records
        lnk_details = []
        for r in lnk:
            lnk_details.append({
                "timestamp": r.get("timestamp", ""),
                "lnk_name": r.get("lnk_name", ""),
                "target_path": r.get("target_path", ""),
                "working_directory": r.get("working_directory", ""),
                "arguments": r.get("arguments", ""),
                "source_created": r.get("source_created", ""),
                "source_modified": r.get("source_modified", ""),
            })

        # Full registry records
        registry_details = []
        for r in registry:
            registry_details.append({
                "timestamp": r.get("timestamp", ""),
                "hive_type": r.get("hive_type", ""),
                "key_path": r.get("key_path", ""),
                "value_name": r.get("value_name", ""),
                "value_data": r.get("value_data", ""),
                "category": r.get("category", ""),
            })

        # Calculate timeline
        all_times = [r["timestamp"] for r in prefetch_details if r["timestamp"]]
        all_times.extend([r["timestamp"] for r in lnk_details if r["timestamp"]])

        return {
            "program": program_name,
            "summary": {
                "prefetch_records": len(prefetch),
                "lnk_records": len(lnk),
                "registry_records": len(registry),
                "first_seen": min(all_times) if all_times else None,
                "last_seen": max(all_times) if all_times else None,
            },
            "prefetch": prefetch_details,
            "lnk_shortcuts": lnk_details,
            "registry_entries": registry_details
        }

    def _tool_analyze_web(self, domain: str = None, limit: int = 100) -> Dict:
        """Analyze web activity - returns FULL records for investigation"""
        results = self._es_search("forensic-browser", domain, limit)

        # Full browser records
        visits = []
        for r in results:
            visits.append({
                "timestamp": r.get("timestamp", ""),
                "browser": r.get("browser", ""),
                "url": r.get("url", ""),
                "title": r.get("title", ""),
                "domain": r.get("domain", ""),
                "visit_count": r.get("visit_count", 0),
                "typed_count": r.get("typed_count", 0),
            })

        # Group by domain for summary
        domains = {}
        for r in results:
            d = r.get("domain", "unknown")
            if d not in domains:
                domains[d] = 0
            domains[d] += r.get("visit_count", 1)

        # Top domains
        top = sorted(domains.items(), key=lambda x: x[1], reverse=True)[:20]

        return {
            "search_query": domain,
            "total_records": len(results),
            "unique_domains": len(domains),
            "top_domains": [{"domain": d, "total_visits": c} for d, c in top],
            "visits": visits  # Full records
        }

    def _tool_find_suspicious(self) -> Dict:
        """Find suspicious activity - comprehensive malware/IOC detection"""
        suspicious = []

        # 1. Executions from TEMP/Downloads - use separate queries
        for search_term in ["TEMP", "Downloads", "AppData"]:
            temp_exec = self._es_search("forensic-prefetch", search_term, 30)
            for r in temp_exec:
                exe_path = r.get("executable_path", "").lower()
                exe_name = r.get("executable_name", "")
                # Check if actually from suspicious location
                if any(x in exe_path for x in ["\\temp\\", "\\downloads\\", "\\appdata\\local\\temp\\"]):
                    suspicious.append({
                        "type": "temp_execution",
                        "severity": "high",
                        "description": f"Program executed from suspicious folder: {exe_name}",
                        "executable_path": r.get("executable_path", ""),
                        "run_count": r.get("run_count", 0),
                        "timestamp": r.get("timestamp", "")
                    })

        # 2. CRITICAL: Search for malware keywords in files_loaded
        malware_keywords = [
            "ransom", "locker", "malware", "virus", "trojan",
            "backdoor", "rootkit", "keylog", "stealer", "miner",
            "botnet", "mimikatz", "lazagne", "bloodhound", "cobalt",
            "payload", "exploit", "reverse", "beacon", "hack"
        ]

        # System files to exclude (false positives)
        system_exclusions = [
            "\\windows\\system32\\", "\\windows\\syswow64\\",
            "\\windows\\winsxs\\", "\\program files\\common files\\",
            ".dll", "bcrypt", "crypt32", "cryptsp", "cryptbase"
        ]

        for keyword in malware_keywords:
            results = self._es_search("forensic-prefetch", keyword, 50)
            for r in results:
                files_loaded = r.get("files_loaded", [])
                exe_name = r.get("executable_name", "")

                # Check if keyword is in files_loaded (exclude system DLLs)
                matched_files = []
                for f in files_loaded:
                    f_lower = f.lower()
                    if keyword.lower() in f_lower:
                        # Skip if it's a system file
                        if not any(excl in f_lower for excl in system_exclusions):
                            matched_files.append(f)

                if matched_files:
                    suspicious.append({
                        "type": "malware_indicator",
                        "severity": "critical",
                        "description": f"Suspicious file loaded by {exe_name}: {keyword}",
                        "executable": exe_name,
                        "executable_path": r.get("executable_path", ""),
                        "matched_files": matched_files[:5],
                        "timestamp": r.get("timestamp", ""),
                        "run_count": r.get("run_count", 0)
                    })

                # Also check executable name itself
                if keyword.lower() in exe_name.lower():
                    suspicious.append({
                        "type": "malware_executable",
                        "severity": "critical",
                        "description": f"Suspicious executable name: {exe_name}",
                        "executable_path": r.get("executable_path", ""),
                        "timestamp": r.get("timestamp", ""),
                        "run_count": r.get("run_count", 0)
                    })

        # 3. Check registry for suspicious keywords
        for keyword in malware_keywords[:10]:  # Top keywords
            reg_results = self._es_search("forensic-registry", keyword, 20)
            for r in reg_results:
                value_data = r.get("value_data", "")
                if keyword.lower() in value_data.lower():
                    suspicious.append({
                        "type": "registry_malware_indicator",
                        "severity": "critical",
                        "description": f"Suspicious registry value contains: {keyword}",
                        "key_path": r.get("key_path", ""),
                        "value_data": value_data[:200],
                        "timestamp": r.get("timestamp", "")
                    })

        # 2. Suspicious Event IDs - use term query for exact match
        suspicious_events = {
            # Critical security events
            1102: ("critical", "Audit log cleared - anti-forensics"),
            4625: ("medium", "Failed login attempt"),
            4648: ("medium", "Explicit credentials used (pass-the-hash?)"),
            4672: ("low", "Special privileges assigned"),
            4688: ("low", "Process creation"),
            4697: ("high", "Service installed"),
            7045: ("high", "Service installed (System)"),
            7036: ("low", "Service state changed"),
            # PowerShell events
            4104: ("high", "PowerShell script block logging"),
        }

        for event_id, (severity, desc) in suspicious_events.items():
            try:
                body = {
                    "size": 30,
                    "query": {"term": {"event_id": event_id}},
                    "sort": [{"timestamp": {"order": "desc"}}]
                }
                response = requests.post(
                    f"{self.es_url}/forensic-eventlog/_search",
                    json=body, timeout=10
                )
                if response.status_code == 200:
                    hits = response.json().get("hits", {}).get("hits", [])
                    for hit in hits:
                        r = hit["_source"]
                        suspicious.append({
                            "type": "suspicious_event",
                            "severity": severity,
                            "event_id": event_id,
                            "description": desc,
                            "message": r.get("message", "")[:200],
                            "timestamp": r.get("timestamp", ""),
                            "provider": r.get("provider", ""),
                            "computer": r.get("computer_name", "")
                        })
            except Exception as e:
                print(f"[ES] Error searching event {event_id}: {e}")

        # 3. Check for suspicious registry entries (Run keys)
        for key_term in ["Run", "RunOnce", "Services"]:
            reg_entries = self._es_search("forensic-registry", key_term, 20)
            for r in reg_entries:
                key_path = r.get("key_path", "").lower()
                if "\\run" in key_path or "\\services" in key_path:
                    suspicious.append({
                        "type": "persistence",
                        "severity": "medium",
                        "description": f"Persistence mechanism: {r.get('key_path', '')[:80]}",
                        "value": r.get("value_data", "")[:100],
                        "timestamp": r.get("timestamp", "")
                    })

        # Remove duplicates based on description+timestamp
        seen = set()
        unique_suspicious = []
        for s in suspicious:
            key = (s.get("description", ""), s.get("timestamp", ""))
            if key not in seen:
                seen.add(key)
                unique_suspicious.append(s)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        unique_suspicious.sort(key=lambda x: severity_order.get(x["severity"], 99))

        return {
            "total_suspicious": len(unique_suspicious),
            "by_severity": {
                "critical": len([s for s in unique_suspicious if s["severity"] == "critical"]),
                "high": len([s for s in unique_suspicious if s["severity"] == "high"]),
                "medium": len([s for s in unique_suspicious if s["severity"] == "medium"]),
                "low": len([s for s in unique_suspicious if s["severity"] == "low"])
            },
            "findings": unique_suspicious[:100]
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

    def _summarize_record(self, record: Dict, search_query: str = None) -> str:
        """Create short summary of a record, highlighting matched terms"""
        art_type = record.get("artifact_type", "")

        if art_type == "prefetch":
            exe = record.get("executable_name", "Unknown")
            if "\\" in exe:
                exe = exe.split("\\")[-1]
            summary = f"Executed: {exe} (run count: {record.get('run_count', 0)})"

            # Check files_loaded for search term matches - CRITICAL for finding ransomware
            files_loaded = record.get("files_loaded", [])
            if search_query and files_loaded:
                query_lower = search_query.lower()
                matched_files = [f for f in files_loaded if query_lower in f.lower()]
                if matched_files:
                    # Show up to 3 matched files with full path
                    matches_str = ", ".join(matched_files[:3])
                    summary += f" | LOADED FILES MATCH: {matches_str}"

            return summary

        elif art_type == "eventlog":
            return f"Event {record.get('event_id', '')} - {record.get('provider', '')} [{record.get('level', '')}]"

        elif art_type == "registry":
            value_data = record.get('value_data', '')
            # Show value_data if it contains search query
            if search_query and search_query.lower() in value_data.lower():
                return f"{record.get('hive_type', '')}: {record.get('key_path', '')[:50]} = {value_data[:100]}"
            return f"{record.get('hive_type', '')}: {record.get('key_path', '')[:60]}..."

        elif art_type == "browser_history":
            return f"{record.get('browser', 'Browser')}: {record.get('title', '')[:40]} | {record.get('domain', '')}"

        elif art_type == "lnk":
            return f"Shortcut: {record.get('lnk_name', '')} -> {record.get('target_path', '')[:50]}"

        return str(record)[:100]

    def _execute_tool(self, tool_name: str, tool_input: Dict) -> str:
        """Execute a tool and return JSON result"""
        try:
            if tool_name == "search_artifacts":
                result = self._tool_search_artifacts(
                    query=tool_input.get("query", ""),
                    artifact_type=tool_input.get("artifact_type", "all"),
                    limit=tool_input.get("limit", 20)
                )
            elif tool_name == "get_timeline":
                result = self._tool_get_timeline(
                    start_time=tool_input.get("start_time"),
                    end_time=tool_input.get("end_time"),
                    limit=tool_input.get("limit", 30)
                )
            elif tool_name == "analyze_program_execution":
                result = self._tool_analyze_program(
                    program_name=tool_input.get("program_name", "")
                )
            elif tool_name == "analyze_web_activity":
                result = self._tool_analyze_web(
                    domain=tool_input.get("domain"),
                    limit=tool_input.get("limit", 30)
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
        Claude will decide which tools to use.
        """
        # Trim history to reduce token usage
        self._trim_history()

        # Add user message
        self.conversation_history.append({
            "role": "user",
            "content": query
        })

        try:
            # Initial request with tools - reduced max_tokens for economy
            response = self.client.messages.create(
                model=self.model,
                max_tokens=2048,  # Reduced from 4096 to save tokens
                system=self.system_prompt,
                tools=self.TOOLS,
                messages=self.conversation_history
            )

            # Handle tool use loop
            while response.stop_reason == "tool_use":
                # Find tool use blocks
                tool_uses = [block for block in response.content if block.type == "tool_use"]

                # Add assistant response to history
                self.conversation_history.append({
                    "role": "assistant",
                    "content": response.content
                })

                # Execute tools and collect results
                tool_results = []
                for tool_use in tool_uses:
                    print(f"[Tool] Executing: {tool_use.name}")
                    result = self._execute_tool(tool_use.name, tool_use.input)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_use.id,
                        "content": result
                    })

                # Add tool results to history
                self.conversation_history.append({
                    "role": "user",
                    "content": tool_results
                })

                # Continue conversation
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=2048,  # Reduced for economy
                    system=self.system_prompt,
                    tools=self.TOOLS,
                    messages=self.conversation_history
                )

            # Extract final text response
            final_text = ""
            for block in response.content:
                if hasattr(block, "text"):
                    final_text += block.text

            # Add final response to history
            self.conversation_history.append({
                "role": "assistant",
                "content": final_text
            })

            return final_text

        except Exception as e:
            return f"Error: {str(e)}"

    def clear_history(self):
        """Clear conversation history"""
        self.conversation_history = []


# CLI interface
if __name__ == "__main__":
    import sys

    print("=" * 50)
    print("Claude Forensic Analyzer (Tool Use)")
    print("=" * 50)

    try:
        analyzer = ClaudeAnalyzer()
        print("[OK] Connected to Claude API")
    except ValueError as e:
        print(f"[ERROR] {e}")
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

            print("\nClaude: Analyzing...\n")
            response = analyzer.analyze(query)

            print(response)
            print()

        except KeyboardInterrupt:
            print("\n\nExiting...")
            break
