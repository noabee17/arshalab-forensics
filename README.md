# ArshaLab - Digital Forensics Platform

AI-powered digital forensics platform for analyzing Windows disk images using TSK (The Sleuth Kit) and Claude AI.

## Features

- **Disk Image Analysis**: Support for E01, RAW, DD forensic image formats
- **Artifact Extraction**: Automated extraction of Windows artifacts via TSK
  - Prefetch files (program execution history)
  - Windows Event Logs (Security, System, Application)
  - Registry hives (SAM, SYSTEM, SOFTWARE, NTUSER.DAT)
  - Browser history (Chrome, Firefox, Edge)
  - LNK shortcut files
- **AI-Powered Investigation**: Claude AI assistant with forensic tools
- **Elasticsearch Storage**: Scalable storage with full-text search
- **Web Interface**: Modern dark-themed UI for investigation

## Architecture

```
tsk-mcp-forensics/
├── web_app.py              # FastAPI web server + WebSocket chat
├── etl_pipeline.py         # Extract-Transform-Load pipeline
├── src/
│   ├── collectors/
│   │   └── tsk_collector.py    # TSK-based file extraction
│   ├── parsers/
│   │   ├── base.py             # Base parser class
│   │   └── parsers.py          # 5 artifact parsers
│   ├── loaders/
│   │   ├── elasticsearch_loader.py  # ES bulk loader
│   │   └── sqlite_loader.py         # SQLite fallback
│   └── llm/
│       └── claude_analyzer.py  # Claude AI with Tool Use
├── tools/                  # External forensic tools (Eric Zimmerman + TSK)
│   ├── sleuthkit/bin/      # TSK binaries (fls, icat, mmls, etc.)
│   ├── PECmd/PECmd.exe     # Prefetch parser
│   ├── EvtxeCmd/EvtxECmd.exe  # Event log parser
│   ├── RECmd/RECmd/RECmd.exe  # Registry parser
│   ├── LECmd/LECmd.exe     # LNK shortcut parser
│   ├── hindsight/dist/hindsight.exe  # Browser history parser
│   └── MFTECmd/MFTECmd.exe # MFT parser (optional)
├── config/
│   └── artifacts.yaml      # Artifact paths configuration
└── output/                 # Extracted and parsed data
```

## Prerequisites

### Required
- Python 3.10+
- Elasticsearch 8.x (running on localhost:9200)
- Anthropic API key (Claude)

### External Tools
Download and place in `tools/` directory:
- [The Sleuth Kit](https://www.sleuthkit.org/) → `tools/sleuthkit/bin/`
- [Eric Zimmerman's Tools](https://ericzimmerman.github.io/):
  - PECmd.exe → `tools/PECmd/PECmd.exe` (Prefetch)
  - EvtxECmd.exe → `tools/EvtxeCmd/EvtxECmd.exe` (Event Logs)
  - RECmd.exe → `tools/RECmd/RECmd/RECmd.exe` (Registry)
  - LECmd.exe → `tools/LECmd/LECmd.exe` (LNK shortcuts)
- [Hindsight](https://github.com/obsidianforensics/hindsight) → `tools/hindsight/dist/hindsight.exe` (Browser)

## Installation

```bash
# Clone repository
git clone https://github.com/yourusername/arshalab-forensics.git
cd arshalab-forensics

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Configure environment
copy .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

## Configuration

### Environment Variables (.env)
```env
ANTHROPIC_API_KEY=sk-ant-...
ES_URL=http://localhost:9200
ES_USERNAME=elastic
ES_PASSWORD=changeme
```

### Elasticsearch Setup
```bash
# Start Elasticsearch (Docker)
docker run -d --name elasticsearch \
  -p 9200:9200 \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  elasticsearch:8.11.0
```

## Usage

### 1. Start the Web Server
```bash
python web_app.py
```
Open http://localhost:8080 in your browser.

### 2. Load Evidence
1. Enter path to disk image (E01, RAW, DD)
2. Select artifacts to extract
3. Click "Begin Investigation"

### 3. AI Investigation
Ask questions in the chat:
- "Find suspicious activity"
- "What programs were executed from TEMP folder?"
- "Show timeline for September 22, 2023"
- "Analyze ransom.exe"

## AI Tools

The Claude analyzer has access to these forensic tools:

| Tool | Description |
|------|-------------|
| `search_artifacts` | Search across all forensic data |
| `get_timeline` | Get chronological events |
| `analyze_program_execution` | Deep analysis of specific program |
| `analyze_web_activity` | Browser history analysis |
| `find_suspicious_activity` | Automated IOC detection |
| `get_case_stats` | Statistics about loaded data |

## Parsers (5 types)

| Parser | Tool | Index | Data |
|--------|------|-------|------|
| **Prefetch** | PECmd.exe | `forensic-prefetch` | Program executions, timestamps, loaded files |
| **Event Logs** | EvtxECmd.exe | `forensic-eventlog` | System events, logins, errors |
| **Registry** | RECmd.exe | `forensic-registry` | Autoruns, services, installed software |
| **Browser** | Hindsight.exe | `forensic-browser` | Chrome, Edge, Firefox history |
| **LNK** | LECmd.exe | `forensic-lnk` | Shortcuts, recent files |

### Key Event IDs
- **4625** - Failed login
- **4648** - Explicit credentials
- **7045** - Service installed
- **1102** - Log cleared

### Artifact Locations
```
Windows/Prefetch/*.pf                              → Prefetch
Windows/System32/winevt/Logs/*.evtx                → Event Logs
Windows/System32/config/{SYSTEM,SOFTWARE,SAM}      → Registry
Users/*/NTUSER.DAT                                 → User Registry
Users/*/AppData/Local/Google/Chrome/.../History    → Chrome
Users/*/AppData/Roaming/Mozilla/.../places.sqlite  → Firefox
Users/*/AppData/Roaming/Microsoft/Windows/Recent/  → LNK
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web interface |
| `/ws` | WebSocket | Real-time chat & processing |
| `/upload` | POST | Upload disk image |
| `/api/data-status` | GET | Elasticsearch status |

## Adding New Parsers

1. Create class in `src/parsers/parsers.py` inheriting `BaseParser`
2. Implement: `name`, `description`, `index_name`, `_parse_impl`, `_normalize_record`
3. Register in `src/parsers/__init__.py`

## License

MIT License

## Credits

- [The Sleuth Kit](https://www.sleuthkit.org/) - Disk forensics
- [Eric Zimmerman's Tools](https://ericzimmerman.github.io/) - Windows artifact parsing
- [Anthropic Claude](https://anthropic.com/) - AI analysis
- [Elasticsearch](https://elastic.co/) - Data storage
