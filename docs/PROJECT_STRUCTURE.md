# Project Structure

```text
scamshield/
├── frontend/
│   ├── src/
│   │   ├── main.jsx
│   │   └── styles.css
│   ├── index.html
│   └── package.json
├── backend/
│   ├── app/
│   │   └── main.py
│   └── requirements.txt
├── docs/
│   └── PROJECT_STRUCTURE.md
├── plan.md
└── README.md
```

## Production evolution

Add these when the project moves beyond the demo:

- `frontend/.env` for the deployed API base URL (never commit secrets).
- `backend/app/model/` for the trained NLP model.
- `backend/app/services/` for URL analysis, scoring and ML inference.
- `backend/tests/` for API tests.
- PostgreSQL for authenticated scan history.
