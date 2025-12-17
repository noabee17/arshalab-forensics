# src/parsers/base.py
"""
BaseParser - Abstract base class for all forensic artifact parsers.

To create a new parser:
1. Inherit from BaseParser
2. Implement properties: name, description, index_name
3. Implement methods: _parse_impl, _normalize_record
4. Register the parser in __init__.py
"""

import os
import json
import csv
import subprocess
import ctypes
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime


def get_short_path(long_path: str) -> str:
    """
    Convert long path to Windows 8.3 short path format.
    This helps avoid encoding issues with non-ASCII characters in paths.
    """
    if os.name != 'nt':
        return long_path

    try:
        # Use Windows API to get short path
        buf = ctypes.create_unicode_buffer(512)
        get_short_path_name = ctypes.windll.kernel32.GetShortPathNameW
        result = get_short_path_name(long_path, buf, 512)
        if result:
            return buf.value
    except Exception:
        pass

    return long_path


class BaseParser(ABC):
    """
    Abstract base class for all forensic artifact parsers.

    Attributes:
        executable_path: Path to parser executable (PECmd, EvtxECmd, etc.)
        output_dir: Directory for temporary output files
    """

    def __init__(self, executable_path: str = None, output_dir: str = "output"):
        """
        Args:
            executable_path: Path to parser exe file (optional for some parsers)
            output_dir: Directory for output files
        """
        self.executable_path = os.path.abspath(executable_path) if executable_path else None
        self.output_dir = os.path.abspath(output_dir)

        if self.executable_path and not os.path.exists(self.executable_path):
            raise FileNotFoundError(f"{self.name} executable not found: {self.executable_path}")

    @property
    @abstractmethod
    def name(self) -> str:
        """Parser name (e.g., 'PrefetchParser')"""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Description of what the parser handles (e.g., 'Windows Prefetch files')"""
        pass

    @property
    @abstractmethod
    def index_name(self) -> str:
        """Elasticsearch index name (e.g., 'forensic-prefetch')"""
        pass

    @abstractmethod
    def _parse_impl(self, input_path: str) -> List[Dict[str, Any]]:
        """
        Internal parsing implementation.

        Args:
            input_path: Path to file or directory with artifacts

        Returns:
            List of dictionaries with parsed data
        """
        pass

    @abstractmethod
    def _normalize_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize record to standard format for Elasticsearch.

        Args:
            record: Raw record from parser

        Returns:
            Normalized record
        """
        pass

    def _safe_print(self, msg: str):
        """Print message with encoding safety for Windows console."""
        try:
            safe_msg = str(msg).encode('cp1252', errors='replace').decode('cp1252')
            print(safe_msg)
        except:
            print(str(msg).encode('ascii', errors='replace').decode('ascii'))

    def parse(self, input_path: str, case_id: str = None) -> List[Dict[str, Any]]:
        """
        Main parsing method. Calls _parse_impl and adds metadata.

        Args:
            input_path: Path to file or directory
            case_id: Case ID for data grouping

        Returns:
            List of normalized records with metadata
        """
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Input path not found: {input_path}")

        self._safe_print(f"[{self.name}] Parsing: {input_path}")

        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)

        # Parse artifacts
        raw_records = self._parse_impl(input_path)

        if not raw_records:
            self._safe_print(f"[{self.name}] No records found")
            return []

        # Normalize and add metadata
        normalized = []
        timestamp = datetime.utcnow().isoformat()

        for record in raw_records:
            normalized_record = self._normalize_record(record)

            # Add common metadata
            normalized_record["_meta"] = {
                "parser": self.name,
                "case_id": case_id or "default",
                "parsed_at": timestamp,
                "source_path": input_path
            }

            normalized.append(normalized_record)

        self._safe_print(f"[{self.name}] Parsed {len(normalized)} records")
        return normalized

    def parse_to_json(self, input_path: str, case_id: str = None) -> str:
        """
        Parse and save to JSON file.

        Returns:
            Path to created JSON file
        """
        records = self.parse(input_path, case_id)

        if not records:
            return None

        # Save JSON
        output_file = os.path.join(
            self.output_dir,
            f"{self.index_name.replace('forensic-', '')}_{case_id or 'default'}.json"
        )

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(records, f, indent=2, ensure_ascii=False, default=str)

        self._safe_print(f"[{self.name}] Saved to: {output_file}")
        return output_file

    # ============== Utility methods for subclasses ==============

    def _run_command(self, cmd: str, timeout: int = 300) -> subprocess.CompletedProcess:
        """Run external command with support for non-ASCII paths."""
        import re

        # Find all quoted paths in command and convert them to short paths
        def convert_path(match):
            path = match.group(1)
            if os.path.exists(path):
                return f'"{get_short_path(path)}"'
            return match.group(0)

        # Convert quoted paths
        cmd_converted = re.sub(r'"([^"]+)"', convert_path, cmd)

        # Safely print command (handle unicode in paths)
        self._safe_print(f"[{self.name}] Running: {cmd_converted[:100]}...")

        result = subprocess.run(
            cmd_converted,
            capture_output=True,
            text=True,
            shell=True,
            timeout=timeout,
            encoding='utf-8',
            errors='ignore'
        )

        if result.returncode != 0 and result.stderr:
            self._safe_print(f"[{self.name}] Warning: {result.stderr[:300]}")

        return result

    def _read_csv(self, csv_path: str) -> List[Dict[str, Any]]:
        """Read CSV file into list of dictionaries."""
        records = []

        try:
            with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    records.append(dict(row))
        except Exception as e:
            self._safe_print(f"[{self.name}] Error reading CSV {csv_path}: {e}")

        return records

    def _find_csv_files(self, directory: str) -> List[str]:
        """Find all CSV files in directory (including subdirectories)."""
        csv_files = []

        if os.path.exists(directory):
            for root, dirs, files in os.walk(directory):
                for f in files:
                    if f.endswith('.csv'):
                        csv_files.append(os.path.join(root, f))

        return csv_files

    def _safe_int(self, value: Any, default: int = 0) -> int:
        """Safe conversion to int."""
        try:
            return int(value) if value else default
        except (ValueError, TypeError):
            return default

    def _safe_str(self, value: Any, max_len: int = None) -> str:
        """Safe conversion to string with optional length limit."""
        s = str(value) if value else ""
        if max_len and len(s) > max_len:
            s = s[:max_len]
        return s
