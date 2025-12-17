# src/parsers/parsers.py
"""
Unified Forensic Artifact Parsers
=================================

All parsers in one file with unified architecture.
Each parser inherits BaseParser and implements a common interface.

Parsers:
- Prefetch_PECmd_Parser: Windows Prefetch via PECmd
- EventLog_EvtxECmd_Parser: Windows Event Logs via EvtxECmd
- Registry_RECmd_Parser: Windows Registry via RECmd
- Browser_SQLite_Parser: Browser History (Chrome, Edge, Firefox)
- LNK_LECmd_Parser: Windows Shortcuts via LECmd

To add a new parser:
1. Create a class inheriting from BaseParser
2. Implement: name, description, index_name, _parse_impl, _normalize_record
3. Add to PARSERS dict in __init__.py
"""

import os
import sqlite3
import shutil
from typing import List, Dict, Any
from datetime import datetime
from .base import BaseParser


# =============================================================================
# PREFETCH PARSER (PECmd)
# =============================================================================

class Prefetch_PECmd_Parser(BaseParser):
    """
    Windows Prefetch files (.pf) parser via PECmd.

    Prefetch files contain program execution information:
    - Executable file name
    - Run time (up to 8 last runs)
    - Files loaded at startup
    - Volume information

    Usage:
        parser = Prefetch_PECmd_Parser("tools/PECmd/PECmd.exe")
        records = parser.parse("C:/Windows/Prefetch")
    """

    @property
    def name(self) -> str:
        return "Prefetch_PECmd_Parser"

    @property
    def description(self) -> str:
        return "Windows Prefetch files - program execution history"

    @property
    def index_name(self) -> str:
        return "forensic-prefetch"

    def _parse_impl(self, input_path: str) -> List[Dict[str, Any]]:
        """Run PECmd and parse results."""
        import glob as glob_module

        if os.path.isfile(input_path):
            cmd = f'"{self.executable_path}" -f "{input_path}" --csv "{self.output_dir}"'
        else:
            cmd = f'"{self.executable_path}" -d "{input_path}" --csv "{self.output_dir}"'

        self._run_command(cmd)

        # Search for CSV files by pattern (PECmd creates timestamp_PECmd_Output*.csv)
        timeline_files = glob_module.glob(os.path.join(self.output_dir, "*_Timeline.csv"))
        main_files = glob_module.glob(os.path.join(self.output_dir, "*_PECmd_Output.csv"))

        # Also check old names for compatibility
        if not timeline_files:
            timeline_files = glob_module.glob(os.path.join(self.output_dir, "prefetch_Timeline.csv"))
        if not main_files:
            main_files = glob_module.glob(os.path.join(self.output_dir, "prefetch.csv"))

        timeline_csv = timeline_files[0] if timeline_files else None
        main_csv = main_files[0] if main_files else None

        # Read metadata from main CSV (here ExecutableName = clean name, e.g. "AI.EXE")
        metadata = {}
        if main_csv and os.path.exists(main_csv):
            for row in self._read_csv(main_csv):
                exe_name = row.get('ExecutableName', '').upper()
                if exe_name:
                    # Volume0Name contains path like \VOLUME{...}
                    volume_info = row.get('Volume0Name', row.get('VolumeInformation', ''))
                    metadata[exe_name] = {
                        'hash': row.get('Hash', ''),
                        'file_path': row.get('SourceFilename', ''),
                        'files_loaded': row.get('FilesLoaded', ''),
                        'volume': volume_info,
                        'run_count': row.get('RunCount', '0')
                    }

        # Read Timeline
        records = []
        if timeline_csv and os.path.exists(timeline_csv):
            for row in self._read_csv(timeline_csv):
                exe_path = row.get('ExecutableName', '')  # Full path: \VOLUME{...}\...\AI.EXE
                run_time = row.get('RunTime', '')

                if exe_path and run_time:
                    # Extract clean exe name from full path for matching with metadata
                    exe_name_clean = os.path.basename(exe_path).upper()

                    record = {
                        'executable_name': exe_name_clean,  # Clean name: AI.EXE
                        'executable_path': exe_path,  # Full path for reference
                        'run_time': run_time,
                        'prefetch_hash': '',
                        'source_file': '',
                        'files_loaded': [],
                        'volume_info': '',
                        'run_count': 0
                    }

                    # Match by clean exe name
                    if exe_name_clean in metadata:
                        meta = metadata[exe_name_clean]
                        record['prefetch_hash'] = meta['hash']
                        record['source_file'] = meta['file_path']
                        record['volume_info'] = meta['volume']
                        record['run_count'] = self._safe_int(meta['run_count'])

                        if meta['files_loaded']:
                            files = [f.strip() for f in meta['files_loaded'].split(',') if f.strip()]
                            record['files_loaded'] = files[:100]

                    records.append(record)

        return records

    def _normalize_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Prefetch record."""
        return {
            "artifact_type": "prefetch",
            "timestamp": record.get('run_time', ''),
            "executable_name": self._safe_str(record.get('executable_name', '')),
            "executable_path": self._safe_str(record.get('executable_path', ''), 500),
            "prefetch_hash": self._safe_str(record.get('prefetch_hash', '')),
            "source_file": self._safe_str(record.get('source_file', '')),
            "run_count": self._safe_int(record.get('run_count', 0)),
            "files_loaded": record.get('files_loaded', []),
            "volume_info": self._safe_str(record.get('volume_info', ''), 500),
        }


# =============================================================================
# EVENT LOG PARSER (EvtxECmd)
# =============================================================================

class EventLog_EvtxECmd_Parser(BaseParser):
    """
    Windows Event Logs (.evtx) parser via EvtxECmd.

    Windows Event Logs contain:
    - System events
    - User logins/logouts
    - Errors and warnings
    - Software installation
    - Network activity

    Usage:
        parser = EventLog_EvtxECmd_Parser("tools/EvtxeCmd/EvtxECmd.exe")
        records = parser.parse("C:/Windows/System32/winevt/Logs")
    """

    @property
    def name(self) -> str:
        return "EventLog_EvtxECmd_Parser"

    @property
    def description(self) -> str:
        return "Windows Event Logs - system events, authentication, errors"

    @property
    def index_name(self) -> str:
        return "forensic-eventlog"

    def _parse_impl(self, input_path: str) -> List[Dict[str, Any]]:
        """Run EvtxECmd and parse results."""
        if os.path.isfile(input_path):
            cmd = f'"{self.executable_path}" -f "{input_path}" --csv "{self.output_dir}" --csvf "eventlog.csv"'
        else:
            cmd = f'"{self.executable_path}" -d "{input_path}" --csv "{self.output_dir}" --csvf "eventlog.csv"'

        self._run_command(cmd, timeout=600)

        records = []
        csv_files = self._find_csv_files(self.output_dir)

        for csv_file in csv_files:
            for row in self._read_csv(csv_file):
                record = {
                    'event_id': row.get('EventId', row.get('Event Id', '')),
                    'timestamp': row.get('TimeCreated', row.get('Timestamp', '')),
                    'provider': row.get('Provider', row.get('Source', '')),
                    'channel': row.get('Channel', ''),
                    'level': row.get('Level', ''),
                    'computer': row.get('Computer', row.get('ComputerName', '')),
                    'user_id': row.get('UserId', row.get('User', '')),
                    'payload': row.get('Payload', row.get('Message', '')),
                    'record_id': row.get('RecordId', row.get('EventRecordId', '')),
                }
                records.append(record)

        return records

    def _normalize_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Event Log record."""
        level = self._safe_str(record.get('level', '')).lower()
        severity = "info"
        if "error" in level or "critical" in level:
            severity = "error"
        elif "warning" in level:
            severity = "warning"

        return {
            "artifact_type": "eventlog",
            "timestamp": self._safe_str(record.get('timestamp', '')),
            "event_id": self._safe_int(record.get('event_id', 0)),
            "provider": self._safe_str(record.get('provider', '')),
            "channel": self._safe_str(record.get('channel', '')),
            "level": self._safe_str(record.get('level', '')),
            "severity": severity,
            "computer_name": self._safe_str(record.get('computer', '')),
            "user_id": self._safe_str(record.get('user_id', '')),
            "message": self._safe_str(record.get('payload', ''), 2000),
            "record_id": self._safe_int(record.get('record_id', 0)),
        }


# =============================================================================
# REGISTRY PARSER (RECmd)
# =============================================================================

class Registry_RECmd_Parser(BaseParser):
    """
    Windows Registry hives parser via RECmd.

    Windows Registry contains:
    - System configuration
    - Installed programs
    - Autorun (Run/RunOnce)
    - User profiles
    - Network settings

    Supported hives: SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, UsrClass.dat

    Usage:
        parser = Registry_RECmd_Parser("tools/RECmd/RECmd/RECmd.exe")
        records = parser.parse("C:/Windows/System32/config")
    """

    def __init__(self, executable_path: str = None, output_dir: str = "output", batch_file: str = None):
        super().__init__(executable_path, output_dir)
        self.batch_file = os.path.abspath(batch_file) if batch_file else None

    @property
    def name(self) -> str:
        return "Registry_RECmd_Parser"

    @property
    def description(self) -> str:
        return "Windows Registry - system config, autoruns, installed software"

    @property
    def index_name(self) -> str:
        return "forensic-registry"

    def _parse_impl(self, input_path: str) -> List[Dict[str, Any]]:
        """Run RECmd and parse results."""
        if os.path.isfile(input_path):
            base_cmd = f'"{self.executable_path}" -f "{input_path}"'
        else:
            base_cmd = f'"{self.executable_path}" -d "{input_path}"'

        if self.batch_file and os.path.exists(self.batch_file):
            base_cmd += f' --bn "{self.batch_file}"'

        cmd = f'{base_cmd} --csv "{self.output_dir}"'
        self._run_command(cmd, timeout=600)

        records = []
        csv_files = self._find_csv_files(self.output_dir)

        for csv_file in csv_files:
            csv_name = os.path.basename(csv_file).upper()

            for row in self._read_csv(csv_file):
                hive_type = self._detect_hive_type(csv_name, row)

                record = {
                    'hive_type': hive_type,
                    'key_path': row.get('KeyPath', row.get('Key', row.get('HivePath', ''))),
                    'value_name': row.get('ValueName', row.get('Value', '')),
                    'value_data': row.get('ValueData', row.get('Data', row.get('ValueData2', row.get('ValueData3', '')))),
                    'value_type': row.get('ValueType', row.get('Type', '')),
                    'last_write': row.get('LastWriteTimestamp', row.get('LastModified', '')),
                    'description': row.get('Description', ''),
                    'category': row.get('Category', ''),
                }
                records.append(record)

        return records

    def _detect_hive_type(self, csv_name: str, row: Dict) -> str:
        """Detect registry hive type."""
        key_path = str(row.get('KeyPath', row.get('Key', ''))).upper()

        if 'SYSTEM' in csv_name or '\\SYSTEM\\' in key_path:
            return "SYSTEM"
        elif 'SOFTWARE' in csv_name or '\\SOFTWARE\\' in key_path:
            return "SOFTWARE"
        elif 'NTUSER' in csv_name or 'NTUSER' in key_path:
            return "NTUSER.DAT"
        elif 'SAM' in csv_name:
            return "SAM"
        elif 'SECURITY' in csv_name:
            return "SECURITY"
        elif 'USRCLASS' in csv_name:
            return "UsrClass.dat"

        return "UNKNOWN"

    def _normalize_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Registry record."""
        category = record.get('category', '')
        if not category:
            key_path = self._safe_str(record.get('key_path', '')).lower()
            if 'run' in key_path:
                category = "autorun"
            elif 'services' in key_path:
                category = "services"
            elif 'uninstall' in key_path:
                category = "installed_software"
            elif 'network' in key_path or 'tcpip' in key_path:
                category = "network"
            else:
                category = "other"

        return {
            "artifact_type": "registry",
            "timestamp": self._safe_str(record.get('last_write', '')),
            "hive_type": self._safe_str(record.get('hive_type', '')),
            "key_path": self._safe_str(record.get('key_path', ''), 1000),
            "value_name": self._safe_str(record.get('value_name', '')),
            "value_data": self._safe_str(record.get('value_data', ''), 1000),
            "value_type": self._safe_str(record.get('value_type', '')),
            "category": category,
            "description": self._safe_str(record.get('description', ''), 500),
        }


# =============================================================================
# BROWSER HISTORY PARSER (SQLite)
# =============================================================================

class Browser_SQLite_Parser(BaseParser):
    """
    Browser history parser (Chrome, Edge, Firefox).

    Works directly with browser SQLite databases.
    Supported browsers: Chrome, Edge, Firefox, Opera, Brave

    Usage:
        parser = Browser_SQLite_Parser()
        records = parser.parse("C:/Users/*/AppData/Local/Google/Chrome/User Data/Default/History")
    """

    BROWSER_PATHS = {
        "chrome": ["AppData/Local/Google/Chrome/User Data/*/History"],
        "edge": ["AppData/Local/Microsoft/Edge/User Data/*/History"],
        "firefox": ["AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite"],
    }

    def __init__(self, executable_path: str = None, output_dir: str = "output"):
        super().__init__(None, output_dir)  # executable not needed

    @property
    def name(self) -> str:
        return "Browser_SQLite_Parser"

    @property
    def description(self) -> str:
        return "Browser History - web browsing activity, URLs, searches"

    @property
    def index_name(self) -> str:
        return "forensic-browser"

    def _parse_impl(self, input_path: str) -> List[Dict[str, Any]]:
        """Parse browser SQLite databases."""
        records = []
        files_to_parse = []

        if os.path.isfile(input_path):
            files_to_parse.append(input_path)
        elif os.path.isdir(input_path):
            for root, dirs, files in os.walk(input_path):
                for f in files:
                    if f.lower() in ('history', 'places.sqlite'):
                        files_to_parse.append(os.path.join(root, f))

        for db_file in files_to_parse:
            browser = self._detect_browser(db_file)
            print(f"[{self.name}] Processing {browser}: {os.path.basename(db_file)}")

            try:
                temp_db = os.path.join(self.output_dir, f"temp_{browser}_{os.getpid()}.db")
                shutil.copy2(db_file, temp_db)

                if browser == "Firefox":
                    browser_records = self._parse_firefox(temp_db, browser)
                else:
                    browser_records = self._parse_chromium(temp_db, browser)

                records.extend(browser_records)
                os.remove(temp_db)

            except Exception as e:
                print(f"[{self.name}] Error parsing {db_file}: {e}")
                continue

        return records

    def _detect_browser(self, file_path: str) -> str:
        """Detect browser by file path and DB structure."""
        path_lower = file_path.lower()

        # First check by path
        if 'chrome' in path_lower:
            return "Chrome"
        elif 'edge' in path_lower:
            return "Edge"
        elif 'firefox' in path_lower or 'places.sqlite' in path_lower:
            return "Firefox"
        elif 'opera' in path_lower:
            return "Opera"
        elif 'brave' in path_lower:
            return "Brave"

        # If not detected by path - analyze DB structure
        try:
            conn = sqlite3.connect(file_path)
            cursor = conn.cursor()

            # Get list of tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0].lower() for row in cursor.fetchall()]
            conn.close()

            # Firefox has moz_places table
            if 'moz_places' in tables:
                return "Firefox"

            # Chromium-based browsers have urls table
            if 'urls' in tables:
                # Could try to detect by meta data or keyword_search_terms
                # But generally this is Chromium-based (Chrome, Edge, Opera, Brave)
                # Default to Chromium as generic
                return "Chromium"

        except Exception as e:
            print(f"[{self.name}] Cannot detect browser from DB structure: {e}")

        return "Unknown"

    def _parse_chromium(self, db_path: str, browser: str) -> List[Dict[str, Any]]:
        """Parse Chromium-based browsers."""
        records = []

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute("""
                SELECT url, title, visit_count, typed_count, last_visit_time, hidden
                FROM urls ORDER BY last_visit_time DESC LIMIT 10000
            """)

            for row in cursor.fetchall():
                timestamp = self._chrome_timestamp_to_iso(row[4])
                records.append({
                    'browser': browser,
                    'url': row[0],
                    'title': row[1],
                    'visit_count': row[2] or 1,
                    'typed_count': row[3] or 0,
                    'visit_time': timestamp,
                    'hidden': bool(row[5]) if row[5] else False,
                })

            conn.close()

        except Exception as e:
            print(f"[{self.name}] Chromium parse error: {e}")

        return records

    def _parse_firefox(self, db_path: str, browser: str) -> List[Dict[str, Any]]:
        """Parse Firefox places.sqlite."""
        records = []

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute("""
                SELECT url, title, visit_count, last_visit_date, hidden
                FROM moz_places WHERE visit_count > 0
                ORDER BY last_visit_date DESC LIMIT 10000
            """)

            for row in cursor.fetchall():
                timestamp = self._firefox_timestamp_to_iso(row[3])
                records.append({
                    'browser': browser,
                    'url': row[0],
                    'title': row[1],
                    'visit_count': row[2] or 1,
                    'typed_count': 0,
                    'visit_time': timestamp,
                    'hidden': bool(row[4]) if row[4] else False,
                })

            conn.close()

        except Exception as e:
            print(f"[{self.name}] Firefox parse error: {e}")

        return records

    def _chrome_timestamp_to_iso(self, timestamp: int) -> str:
        """Convert Chrome timestamp to ISO format."""
        if not timestamp:
            return ""
        try:
            unix_timestamp = (timestamp / 1000000) - 11644473600
            dt = datetime.utcfromtimestamp(unix_timestamp)
            return dt.isoformat() + "Z"
        except:
            return ""

    def _firefox_timestamp_to_iso(self, timestamp: int) -> str:
        """Convert Firefox timestamp to ISO format."""
        if not timestamp:
            return ""
        try:
            dt = datetime.utcfromtimestamp(timestamp / 1000000)
            return dt.isoformat() + "Z"
        except:
            return ""

    def _normalize_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Browser History record."""
        url = self._safe_str(record.get('url', ''))

        domain = ""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc
        except:
            pass

        return {
            "artifact_type": "browser_history",
            "timestamp": self._safe_str(record.get('visit_time', '')),
            "browser": self._safe_str(record.get('browser', '')),
            "url": url,
            "domain": domain,
            "title": self._safe_str(record.get('title', ''), 500),
            "visit_count": self._safe_int(record.get('visit_count', 1)),
            "typed_count": self._safe_int(record.get('typed_count', 0)),
            "hidden": bool(record.get('hidden', False)),
        }


# =============================================================================
# LNK PARSER (LECmd)
# =============================================================================

class LNK_LECmd_Parser(BaseParser):
    """
    Windows LNK (shortcut) files parser via LECmd.

    LNK files contain:
    - Target file path
    - Working directory
    - Command line arguments
    - Timestamps (creation, access, modification)
    - MAC addresses (sometimes)

    Usage:
        parser = LNK_LECmd_Parser("tools/LECmd/LECmd.exe")
        records = parser.parse("C:/Users/*/Recent")
    """

    @property
    def name(self) -> str:
        return "LNK_LECmd_Parser"

    @property
    def description(self) -> str:
        return "Windows LNK shortcuts - recently accessed files and locations"

    @property
    def index_name(self) -> str:
        return "forensic-lnk"

    def _parse_impl(self, input_path: str) -> List[Dict[str, Any]]:
        """Run LECmd and parse results."""
        if os.path.isfile(input_path):
            cmd = f'"{self.executable_path}" -f "{input_path}" --csv "{self.output_dir}" --csvf "lnk.csv"'
        else:
            cmd = f'"{self.executable_path}" -d "{input_path}" --csv "{self.output_dir}" --csvf "lnk.csv"'

        self._run_command(cmd)

        records = []
        csv_files = self._find_csv_files(self.output_dir)

        for csv_file in csv_files:
            for row in self._read_csv(csv_file):
                # Determine target_path with priority for Unicode fields
                # LocalPath may contain corrupted non-ASCII characters
                # TargetIDAbsolutePath usually contains correct Unicode
                local_path = row.get('LocalPath', '')
                target_id_path = row.get('TargetIDAbsolutePath', '')
                working_dir = row.get('WorkingDirectory', '')

                # Check if LocalPath contains corrupted characters
                # (if there are non-ASCII and they are not correct Unicode)
                target_path = local_path
                if target_id_path:
                    # If TargetIDAbsolutePath exists and contains filename,
                    # combine with working directory for full path
                    if working_dir and not target_id_path.startswith(('C:', 'D:', 'E:', '\\', '/')):
                        target_path = os.path.join(working_dir, target_id_path)
                    elif target_id_path.startswith(('C:', 'D:', 'E:', '\\')):
                        target_path = target_id_path
                    # Otherwise use LocalPath if available
                    elif not local_path:
                        target_path = target_id_path

                record = {
                    'lnk_name': row.get('SourceFile', row.get('SourceFilename',
                                row.get('LnkName', row.get('FileName', '')))),
                    'target_path': target_path,
                    'target_name': target_id_path,  # Store filename separately
                    'working_directory': working_dir,
                    'arguments': row.get('Arguments', row.get('CommandLineArguments', '')),
                    'target_created': row.get('TargetCreated', row.get('TargetCreationDate', '')),
                    'target_modified': row.get('TargetModified', row.get('TargetModificationDate', '')),
                    'target_accessed': row.get('TargetAccessed', row.get('TargetAccessDate', '')),
                    'source_created': row.get('SourceCreated', row.get('CreationTime', '')),
                    'source_modified': row.get('SourceModified', row.get('ModifiedTime', '')),
                    'source_accessed': row.get('SourceAccessed', row.get('AccessTime', '')),
                    'file_size': row.get('FileSize', row.get('TargetFileSize', '')),
                    'drive_type': row.get('DriveType', ''),
                    'volume_label': row.get('VolumeLabel', row.get('VolumeName', '')),
                    'volume_serial': row.get('VolumeSerialNumber', row.get('VolumeSerial', '')),
                    'machine_id': row.get('MachineID', row.get('MachineMACAddress', row.get('TrackerCreatedMachineMac', ''))),
                    'relative_path': row.get('RelativePath', ''),
                }

                if record['lnk_name']:
                    record['lnk_name'] = os.path.basename(record['lnk_name'])

                records.append(record)

        return records

    def _normalize_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize LNK record."""
        timestamp = (
            record.get('target_accessed') or
            record.get('source_accessed') or
            record.get('source_modified') or
            ''
        )

        target_path = self._safe_str(record.get('target_path', ''))
        target_name = self._safe_str(record.get('target_name', ''))
        target_ext = ""

        # Determine extension from target_name (more reliable) or target_path
        ext_source = target_name if target_name else target_path
        if ext_source:
            _, ext = os.path.splitext(ext_source)
            target_ext = ext.lower()

        return {
            "artifact_type": "lnk",
            "timestamp": self._safe_str(timestamp),
            "lnk_name": self._safe_str(record.get('lnk_name', '')),
            "target_path": target_path,
            "target_name": target_name,
            "target_extension": target_ext,
            "working_directory": self._safe_str(record.get('working_directory', '')),
            "arguments": self._safe_str(record.get('arguments', ''), 500),
            "target_created": self._safe_str(record.get('target_created', '')),
            "target_modified": self._safe_str(record.get('target_modified', '')),
            "target_accessed": self._safe_str(record.get('target_accessed', '')),
            "source_created": self._safe_str(record.get('source_created', '')),
            "source_modified": self._safe_str(record.get('source_modified', '')),
            "source_accessed": self._safe_str(record.get('source_accessed', '')),
            "file_size": self._safe_int(record.get('file_size', 0)),
            "drive_type": self._safe_str(record.get('drive_type', '')),
            "volume_label": self._safe_str(record.get('volume_label', '')),
            "volume_serial": self._safe_str(record.get('volume_serial', '')),
            "machine_id": self._safe_str(record.get('machine_id', '')),
        }


# =============================================================================
# LEGACY ALIASES (for backward compatibility)
# =============================================================================

# Old class names for backward compatibility
PrefetchParser = Prefetch_PECmd_Parser
EventLogParser = EventLog_EvtxECmd_Parser
RegistryParser = Registry_RECmd_Parser
BrowserHistoryParser = Browser_SQLite_Parser
LnkParser = LNK_LECmd_Parser
