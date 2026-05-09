from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from flask import Flask, Response, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

from ids_engine import analyze_file


BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
DATA_DIR = BASE_DIR / "data"
SAMPLE_LOG = BASE_DIR / "samples" / "sample_mixed.log"
INDICATORS = DATA_DIR / "blocklist.txt"


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024


def ensure_directories() -> None:
    UPLOAD_DIR.mkdir(exist_ok=True)


def run_analysis(log_path: Path) -> dict:
    result = analyze_file(log_path, INDICATORS)
    result["source_file"] = str(log_path)
    result["generated_at"] = datetime.now().isoformat(sep=" ", timespec="seconds")
    return result


@app.get("/")
def index():
    result = run_analysis(SAMPLE_LOG)
    return render_template("index.html", result=result, uploaded=False)


@app.post("/analyze")
def analyze_upload():
    ensure_directories()
    uploaded = request.files.get("log_file")
    if not uploaded or not uploaded.filename:
        return redirect(url_for("index"))

    filename = secure_filename(uploaded.filename)
    destination = UPLOAD_DIR / f"{uuid4().hex}_{filename}"
    uploaded.save(destination)
    result = run_analysis(destination)
    return render_template("index.html", result=result, uploaded=True)


@app.get("/api/sample")
def api_sample():
    return run_analysis(SAMPLE_LOG)


@app.post("/api/analyze")
def api_analyze():
    ensure_directories()
    uploaded = request.files.get("log_file")
    if not uploaded or not uploaded.filename:
        return {"error": "Upload a file using the log_file form field."}, 400

    filename = secure_filename(uploaded.filename)
    destination = UPLOAD_DIR / f"{uuid4().hex}_{filename}"
    uploaded.save(destination)
    return run_analysis(destination)


@app.get("/export/sample.json")
def export_sample():
    payload = json.dumps(run_analysis(SAMPLE_LOG), indent=2)
    return Response(
        payload,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=ids-alerts-sample.json"},
    )


if __name__ == "__main__":
    ensure_directories()
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
