# IDS assignment

## BT3 Core Engine

Core Engine only reads the normalized event and flow summary from BT1-BT2. It does not read Scapy packets directly.

- `core/rule_parser.py`: parses and validates the supported Snort rule subset.
- `core/rule_loader.py`: loads rule files and records invalid, unsupported, disabled rules.
- `core/core_engine.py`: indexes rules, matches headers/flow/content/TCP fields, and creates Detection Events.

Run all BT3 tests:

```powershell
python test_bt3.py
```

Run the capture pipeline with rules:

```powershell
python main.py --pcap TEST/test_http_get.pcap --rules rules/bt3.rules
```

Use `--disable-sid 100001` to turn off an individual rule. Test results are stored in `TEST/BT3/`.

## AI disclosure

- Gemini 3.8 Flash: generated the existing PCAP test fixtures and helper test scripts for BT1-BT2.
- OpenAI Codex: reviewed the BT3 specification, implemented the three-file Core Engine, connected it to the existing pipeline, and added/ran the BT3 tests.

The repository owner should understand and be able to explain all submitted code.
