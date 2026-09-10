from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import sys
from pathlib import Path

from pypdf import PdfReader


# Allow backend to import files from the backend folder
BACKEND_DIR = Path(__file__).resolve().parents[1]

if str(BACKEND_DIR) not in sys.path:
    sys.path.append(str(BACKEND_DIR))

from document_analyzer import analyze_document


# --------------------------------
# FastAPI application
# --------------------------------

app = FastAPI(
    title="ScamShield API",
    version="2.0.0"
)


# --------------------------------
# CORS
# --------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------
# Request model
# --------------------------------

class AnalyzeRequest(BaseModel):
    text: str


# --------------------------------
# Health check
# --------------------------------

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "scamshield-api"
    }


# --------------------------------
# Text analysis
# --------------------------------

@app.post("/analyze")
def analyze(payload: AnalyzeRequest):

    text = payload.text.strip()

    if not text:
        return {
            "error": "No text provided"
        }

    result = analyze_document(text)

    return result


# --------------------------------
# PDF analysis
# --------------------------------

@app.post("/analyze-pdf")
async def analyze_pdf(file: UploadFile = File(...)):

    if not file.filename.lower().endswith(".pdf"):
        return {
            "error": "Please upload a PDF file"
        }

    try:

        contents = await file.read()

        # Save temporarily in memory
        import io

        pdf_stream = io.BytesIO(contents)

        reader = PdfReader(pdf_stream)

        text = "\n\n".join(
            page.extract_text() or ""
            for page in reader.pages
        )

        if not text.strip():
            return {
                "error": "Could not extract text from this PDF"
            }

        result = analyze_document(text)

        result["filename"] = file.filename
        result["pages"] = len(reader.pages)
        result["extracted_characters"] = len(text)

        return result

    except Exception as e:

        return {
            "error": f"PDF analysis failed: {str(e)}"
        }