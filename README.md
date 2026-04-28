# ODLABOT

ODLABOT is a CLI log analyzer bot that:
- accepts user-provided input files (`.log`, `.txt`, `.csv`, `.xlsx`, `.xls`),
- analyzes errors/warnings and recurring patterns,
- suggests practical search steps to investigate failures,
- asks for additional debugging context (ticket, history, verification tests),
- generates a simple stakeholder-ready email summary,
- optionally uses OpenRouter LLM for enhanced analysis and email draft.

## Compatibility

ODLABOT is currently tested for `Python 3.7.x`. If you are using another Python version, create a `3.7.x` virtual environment before installing dependencies.

## Setup

1. Install `Python 3.7.x`.
2. Clone the repository.
3. Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

4. Install dependencies:

```powershell
pip install -r .\requirements.txt
```

5. If you want OpenRouter-enhanced analysis, add your API key to `.env`:

```env
OPENROUTER_API_KEY=your_api_key_here
OPENROUTER_MODEL=openai/gpt-4o-mini
```

6. Run the CLI or Streamlit UI.

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

## OpenRouter API Key

To use the OpenRouter-enhanced mode, you need an OpenRouter API key.
OpenRouter's API key docs are here: [Authentication](https://openrouter.ai/docs/api-keys) and [Create a new API key](https://openrouter.ai/docs/api/api-reference/api-keys/create-keys).

1. Sign in to your OpenRouter account.
2. Open the API keys page in the OpenRouter dashboard.
3. Create a new key, give it a name, and optionally set a spending limit.
4. Copy the key once and store it safely.
5. Add it to your `.env` file.

You can also set it for the current PowerShell session:

```powershell
$env:OPENROUTER_API_KEY="your_api_key_here"
```

## OpenRouter LLM mode

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
