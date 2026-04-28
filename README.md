# ODLABOT

ODLABOT is a CLI log analyzer bot that:
- accepts user-provided input files (`.log`, `.txt`, `.csv`, `.xlsx`, `.xls`),
- analyzes errors/warnings and recurring patterns,
- suggests practical search steps to investigate failures,
- asks for additional debugging context (ticket, history, verification tests),
- generates a simple stakeholder-ready email summary,
- optionally uses OpenRouter LLM for enhanced analysis and email draft.

## Run

```powershell
python .\odlabot.py .\sample.log
```

Or run without arguments and provide the log path interactively:

```powershell
python .\odlabot.py
```

## Streamlit UI

Run the web UI:

```powershell
streamlit run .\app.py
```

Then upload a file (`.log`, `.txt`, `.csv`, `.xlsx`, `.xls`) in the browser and use the form fields for ticket/history/verification context.

## OpenRouter LLM mode

Install dependencies:

```powershell
pip install -r .\requirements.txt
```

Python compatibility in this repo is currently pinned for `Python 3.7.x`.

Set API key in `.env`:

```env
OPENROUTER_API_KEY=your_api_key_here
OPENROUTER_MODEL=openai/gpt-4o-mini
```

Or set via shell:

```powershell
$env:OPENROUTER_API_KEY="your_api_key_here"
```

Run with LLM enabled:

```powershell
python .\odlabot.py .\sample.log --use-llm
```

Optional model override:

```powershell
python .\odlabot.py .\sample.log --use-llm --openrouter-model "openai/gpt-4o-mini"
```

## Typical flow

1. Provide log file path.
2. Review technical summary and top recurring errors.
3. Follow suggested `rg` search patterns.
4. Enter optional debug context:
   - ongoing ticket details,
   - previous node/service history,
   - verification test results,
   - any extra notes.
5. Copy the generated email summary to share with stakeholders.

## Notes

- Input files supported: `.log`, `.txt`, `.csv`, `.xlsx`, `.xls`.
- Uses heuristic pattern matching (severity keywords, component hints, and normalized signatures).
- If OpenRouter fails or no API key is set, ODLABOT falls back to built-in heuristic summaries.
