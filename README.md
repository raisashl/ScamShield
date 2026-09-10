# ScamShield

A responsive, interactive scam and phishing risk analyzer designed as a portfolio-ready software engineering + AI/NLP project.

## What is included

- `frontend/` — polished responsive React/Vite web app.
- `backend/` — FastAPI API foundation for replacing the demo browser rules with a real ML/NLP model.
- `docs/` — project documentation.
- `plan.md` — implementation roadmap.

## Important architecture decision

The frontend works immediately with a browser-based demo analyzer, so the UI is not dependent on a local backend. The backend is included separately as the production/API layer. This makes the project easy to deploy as a static frontend first and then connect to an AI backend when the ML model is ready.

## Run the frontend locally for development

Requirements: Node.js 18+

```bash
cd frontend
npm install
npm run dev
```

For a production build:

```bash
npm run build
```

The generated `frontend/dist` folder can be deployed to Vercel, Netlify, Cloudflare Pages, GitHub Pages (with suitable routing), or another static hosting provider.

## Run the API

Requirements: Python 3.10+

```bash
cd backend
python -m venv .venv
```

Windows:
```bash
.venv\\Scripts\\activate
```

macOS/Linux:
```bash
source .venv/bin/activate
```

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

The API exposes `/health` and `/analyze`.

## Next AI upgrade

Replace the simple rule engine with:
1. A labeled scam/legitimate dataset.
2. Text preprocessing.
3. TF-IDF + Logistic Regression baseline.
4. Evaluation with precision, recall and F1.
5. Optional Transformer/BERT model.
6. Combine ML probability + rule signals + URL features into the final risk score.

## Deployment direction

For a real online application, deploy the frontend to a static hosting platform and the FastAPI service to a cloud platform. Then configure the frontend API base URL through an environment variable. Do not put API keys or secrets in the frontend.
