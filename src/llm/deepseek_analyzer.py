# src/llm/deepseek_analyzer.py
"""
DeepSeek Analyzer - LLM-powered forensic analysis with Tool Use
Very cheap: $0.27/1M input, $1.10/1M output
"""

import os
import json
import requests
from typing import Dict, List, Any
from datetime import datetime

from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()


class DeepSeekAnalyzer:
    """
    Forensic analyzer using DeepSeek API (OpenAI-compatible).
    Very affordable pricing with good Tool Use support.
    """

    SYSTEM_PROMPT = """You are an expert digital forensics analyst investigating Windows disk images.

You have access to tools to query forensic data stored in Elasticsearch. ALWAYS use tools to get real data - never make assumptions.

AVAILABLE DATA:
- Prefetch: Program execution history (what ran, when, how many times)
- EventLog: Windows events (logins, errors, service installs, security)
- Registry: System configuration, user activity, installed software
- Browser: Web browsing history with timestamps
- LNK: Shortcuts showing recently accessed files/programs

═══════════════════════════════════════════════════════════════
INVESTIGATION METHODOLOGY - FOLLOW THIS STRICTLY:
═══════════════════════════════════════════════════════════════

STEP 1: INITIAL ASSESSMENT
- Call get_case_stats FIRST to understand available data
- Call find_suspicious_activity to identify immediate red flags

STEP 2: DEEP INVESTIGATION (call multiple tools)
- search_artifacts for each keyword/IOC from user's briefing
- analyze_web_activity to see browser history and domains visited
- analyze_program_execution for suspicious programs
- get_timeline with specific date ranges

STEP 3: BUILD COMPREHENSIVE TIMELINE
- Combine all findings chronologically
- Show correlation between different artifact types
- Example: Browser search → Download → Program execution → File access

STEP 4: PRESENT FINDINGS
Format your response as:

📋 **CASE SUMMARY**
[1-2 sentences about what happened]

🔍 **KEY FINDINGS**
1. [Finding with timestamp and evidence source]
2. [Finding with timestamp and evidence source]
...

📅 **ACTIVITY TIMELINE**
| Time | Activity | Source |
|------|----------|--------|
| YYYY-MM-DD HH:MM | Event description | artifact type |

⚠️ **SUSPICIOUS INDICATORS**
- [List of IOCs found]

🔗 **CORRELATION ANALYSIS**
[How different artifacts connect - show the attack chain or user activity flow]

💡 **CONCLUSIONS**
[What the evidence tells us]

═══════════════════════════════════════════════════════════════
CRITICAL RULES:
═══════════════════════════════════════════════════════════════
1. ALWAYS call 3-5 tools before answering - one tool is NOT enough
2. ALWAYS include specific timestamps in findings
3. ALWAYS correlate browser history with program execution
4. ALWAYS check for suspicious Event IDs: 4624/4625 (logins), 7045 (services), 1102 (log cleared)
5. For incident investigation - find the ROOT CAUSE within 1-2 questions
6. Present data in tables when showing timelines
7. Quote exact file paths and URLs from evidence"""

    TOOLS = [
        {
            "type": "function",
            "function": {
                "name": "search_artifacts",
                "description": "Search forensic artifacts (prefetch, eventlog, registry, browser, lnk). Use for finding specific programs, files, URLs, or keywords.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query (program name, URL, keyword)"
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
                "description": "Get chronological timeline of events for reconstructing activity.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "start_time": {
                            "type": "string",
                            "description": "Start time (ISO format: 2023-09-22T00:00:00)"
                        },
                        "end_time": {
                            "type": "string",
                            "description": "End time (ISO format: 2023-09-22T23:59:59)"
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
                "description": "Deep analysis of a specific program's execution history.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "program_name": {
                            "type": "string",
                            "description": "Program name (e.g., chrome.exe, cmd.exe)"
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
                "description": "Analyze browser history - visited sites, domains, patterns.",
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
                "description": "Find suspicious activity: TEMP executions, suspicious Event IDs (4625, 4648, 7045, 1102).",
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
                "description": "Get statistics about available forensic data. CALL THIS FIRST to understand the case.",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "get_full_timeline",
                "description": "Build comprehensive timeline combining ALL artifact types. Use this to see the complete picture of user activity.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "hours_back": {
                            "type": "integer",
                            "description": "How many hours back from the most recent activity (default: 24)"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum events (default: 50)"
                        }
                    }
                }
            }
        }
    ]

    def __init__(self, es_url: str = "http://localhost:9200"):
        self.api_key = os.getenv("DEEPSEEK_API_KEY")
        if not self.api_key:
            raise ValueError("DEEPSEEK_API_KEY not found. Get key at https://platform.deepseek.com")

        self.client = OpenAI(
            api_key=self.api_key,
            base_url="https://api.deepseek.com"
        )
        self.es_url = es_url
        self.model = "deepseek-chat"  # DeepSeek V3
        self.conversation_history: List[Dict] = []
        self.max_history_messages = 10

    def _trim_history(self):
        """Keep only last N messages"""
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
            else:
                body["query"] = {"match_all": {}}

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

    def _tool_analyze_web(self, domain: str = None, limit: int = 50) -> Dict:
        """Analyze web activity with detailed timeline"""
        results = self._es_search("forensic-browser", domain, limit)

        domains = {}
        timeline = []

        for r in results:
            d = r.get("domain", "unknown")
            if d not in domains:
                domains[d] = {"count": 0, "first_visit": None, "last_visit": None, "visits": []}
            domains[d]["count"] += r.get("visit_count", 1)

            visit_time = r.get("timestamp", "")
            if not domains[d]["first_visit"] or visit_time < domains[d]["first_visit"]:
                domains[d]["first_visit"] = visit_time
            if not domains[d]["last_visit"] or visit_time > domains[d]["last_visit"]:
                domains[d]["last_visit"] = visit_time

            domains[d]["visits"].append({
                "url": r.get("url", ""),
                "title": r.get("title", ""),
                "time": visit_time
            })

            timeline.append({
                "timestamp": visit_time,
                "domain": d,
                "title": r.get("title", "")[:60],
                "url": r.get("url", "")
            })

        # Sort timeline chronologically
        timeline.sort(key=lambda x: x["timestamp"])

        top = sorted(domains.items(), key=lambda x: x[1]["count"], reverse=True)[:20]

        return {
            "total_records": len(results),
            "unique_domains": len(domains),
            "top_domains": [
                {
                    "domain": d,
                    "visits": v["count"],
                    "first_visit": v["first_visit"],
                    "last_visit": v["last_visit"]
                }
                for d, v in top
            ],
            "browsing_timeline": timeline[:30],
            "recent_searches": [
                t for t in timeline
                if "search" in t["url"].lower() or "google.com/search" in t["url"].lower()
            ][:10]
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
                    "description": f"Executed from temp: {exe}",
                    "timestamp": r.get("timestamp", "")
                })

        # Suspicious Event IDs
        for event_id in [4625, 4648, 7045, 1102]:
            events = self._es_search("forensic-eventlog", str(event_id), 15)
            for r in events:
                if r.get("event_id") == event_id:
                    severity = "high" if event_id in [7045, 1102] else "medium"
                    descriptions = {
                        4625: "Failed login",
                        4648: "Explicit credentials",
                        7045: "Service installed",
                        1102: "Audit log cleared"
                    }
                    suspicious.append({
                        "type": "suspicious_event",
                        "severity": severity,
                        "description": f"Event {event_id}: {descriptions.get(event_id, '')}",
                        "timestamp": r.get("timestamp", "")
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

        # Get time range of data
        time_range = self._get_data_time_range()

        return {
            "total_records": total,
            "by_artifact_type": stats,
            "data_time_range": time_range,
            "status": "data_available" if total > 0 else "no_data"
        }

    def _get_data_time_range(self) -> Dict:
        """Get min/max timestamps from all data"""
        try:
            body = {
                "size": 0,
                "aggs": {
                    "min_time": {"min": {"field": "timestamp"}},
                    "max_time": {"max": {"field": "timestamp"}}
                }
            }
            response = requests.post(f"{self.es_url}/forensic-*/_search", json=body, timeout=5)
            if response.status_code == 200:
                aggs = response.json().get("aggregations", {})
                return {
                    "earliest": aggs.get("min_time", {}).get("value_as_string", ""),
                    "latest": aggs.get("max_time", {}).get("value_as_string", "")
                }
        except:
            pass
        return {}

    def _tool_get_full_timeline(self, hours_back: int = 24, limit: int = 50) -> Dict:
        """Build comprehensive timeline from all artifact types"""
        all_events = []

        # Get recent browser history
        browser = self._es_search("forensic-browser", None, 30)
        for r in browser:
            all_events.append({
                "timestamp": r.get("timestamp", ""),
                "type": "BROWSER",
                "description": f"Visited: {r.get('title', '')[:50]} ({r.get('domain', '')})",
                "details": {"url": r.get("url", ""), "browser": r.get("browser", "")}
            })

        # Get program executions
        prefetch = self._es_search("forensic-prefetch", None, 30)
        for r in prefetch:
            exe = r.get("executable_name", "")
            all_events.append({
                "timestamp": r.get("timestamp", ""),
                "type": "EXECUTION",
                "description": f"Executed: {exe.split(chr(92))[-1] if chr(92) in exe else exe}",
                "details": {"run_count": r.get("run_count", 0), "source": r.get("source_file", "")}
            })

        # Get file access (LNK)
        lnk = self._es_search("forensic-lnk", None, 20)
        for r in lnk:
            all_events.append({
                "timestamp": r.get("timestamp", ""),
                "type": "FILE_ACCESS",
                "description": f"Accessed: {r.get('target_path', '')[:60]}",
                "details": {"lnk_name": r.get("lnk_name", "")}
            })

        # Get important events (security-related)
        for event_id in [4624, 4625, 4648, 7045, 1102, 4688]:
            events = self._es_search("forensic-eventlog", str(event_id), 10)
            event_names = {
                4624: "Login Success",
                4625: "Login Failed",
                4648: "Explicit Credentials",
                7045: "Service Installed",
                1102: "Audit Log Cleared",
                4688: "Process Created"
            }
            for r in events:
                if r.get("event_id") == event_id:
                    all_events.append({
                        "timestamp": r.get("timestamp", ""),
                        "type": "SECURITY_EVENT",
                        "description": f"Event {event_id}: {event_names.get(event_id, '')}",
                        "details": {"provider": r.get("provider", ""), "message": r.get("message", "")[:100]}
                    })

        # Sort by timestamp
        all_events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

        return {
            "total_events": len(all_events),
            "timeline": all_events[:limit],
            "summary": {
                "browser_events": len([e for e in all_events if e["type"] == "BROWSER"]),
                "executions": len([e for e in all_events if e["type"] == "EXECUTION"]),
                "file_access": len([e for e in all_events if e["type"] == "FILE_ACCESS"]),
                "security_events": len([e for e in all_events if e["type"] == "SECURITY_EVENT"])
            }
        }

    def _summarize_record(self, record: Dict) -> str:
        """Create short summary of a record"""
        art_type = record.get("artifact_type", "")

        if art_type == "prefetch":
            exe = record.get("executable_name", "Unknown")
            if "\\" in exe:
                exe = exe.split("\\")[-1]
            return f"Executed: {exe} (runs: {record.get('run_count', 0)})"

        elif art_type == "eventlog":
            return f"Event {record.get('event_id', '')} - {record.get('provider', '')} [{record.get('level', '')}]"

        elif art_type == "registry":
            return f"{record.get('hive_type', '')}: {record.get('key_path', '')[:60]}"

        elif art_type == "browser_history":
            return f"{record.get('browser', '')}: {record.get('title', '')[:40]} | {record.get('domain', '')}"

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
            elif tool_name == "get_full_timeline":
                result = self._tool_get_full_timeline(
                    hours_back=tool_args.get("hours_back", 24),
                    limit=tool_args.get("limit", 50)
                )
            else:
                result = {"error": f"Unknown tool: {tool_name}"}

            return json.dumps(result, ensure_ascii=True, default=str)

        except Exception as e:
            return json.dumps({"error": str(e)})

    # ==================== MAIN ANALYZE METHOD ====================

    def analyze(self, query: str, case_id: str = None) -> str:
        """Analyze forensic data based on user query."""
        self._trim_history()

        # Add user message to history
        self.conversation_history.append({
            "role": "user",
            "content": query
        })

        try:
            # Build messages for this request
            # Use only user/assistant messages from history (no tool calls)
            messages = [{"role": "system", "content": self.SYSTEM_PROMPT}]
            for msg in self.conversation_history:
                if msg["role"] in ["user", "assistant"] and "tool_calls" not in msg:
                    messages.append({"role": msg["role"], "content": msg["content"]})

            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                tools=self.TOOLS,
                tool_choice="auto",
                max_tokens=4096
            )

            message = response.choices[0].message

            # Handle tool calls in a separate loop (not saved to history)
            tool_messages = list(messages)  # Copy for tool loop

            while message.tool_calls:
                # Add assistant message with tool calls
                tool_messages.append({
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

                    print(f"[Tool] {tool_name}")
                    result = self._execute_tool(tool_name, tool_args)

                    tool_messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": result
                    })

                # Continue conversation with tools
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=tool_messages,
                    tools=self.TOOLS,
                    tool_choice="auto",
                    max_tokens=4096
                )
                message = response.choices[0].message

            final_text = message.content or ""

            # Save only the final response to history (no tool details)
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


if __name__ == "__main__":
    print("=" * 50)
    print("DeepSeek Forensic Analyzer")
    print("=" * 50)

    try:
        analyzer = DeepSeekAnalyzer()
        print("[OK] Connected to DeepSeek API")
    except ValueError as e:
        print(f"[ERROR] {e}")
        exit(1)

    print("\nCommands: /clear, /quit\n")

    while True:
        try:
            query = input("You: ").strip()
            if not query:
                continue
            if query == "/quit":
                break
            if query == "/clear":
                analyzer.clear_history()
                print("[Cleared]\n")
                continue

            print("\nAnalyzing...\n")
            print(analyzer.analyze(query))
            print()
        except KeyboardInterrupt:
            break
