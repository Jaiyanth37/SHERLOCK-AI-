from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
import os
import tempfile

from engine.rules import analyze_threat
from engine.knowledge import THREAT_KNOWLEDGE
from engine.forensics import analyze_file


app = Flask(__name__)


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    return render_template(
        "index.html",
        situation="",
        result=None,
        knowledge=THREAT_KNOWLEDGE
    )


# ============================================================
# THREAT ANALYSIS
# ============================================================

@app.route("/analyze", methods=["POST"])
def analyze():

    # Support JSON requests from Sherlock frontend
    if request.is_json:

        data = request.get_json(silent=True) or {}

        situation = (
            data.get("threat")
            or data.get("input")
            or data.get("situation")
            or ""
        ).strip()

    else:

        situation = (
            request.form.get("situation", "")
            or request.form.get("threat", "")
            or request.form.get("input", "")
        ).strip()


    if not situation:

        return jsonify({
            "success": False,
            "error": "No threat indicator supplied."
        }), 400


    # Send the user's input to Sherlock's reasoning engine
    result = analyze_threat(situation)


    return jsonify({
        "success": True,
        "result": result
    })



# ============================================================
# MEDIA FORENSICS API
# ============================================================

@app.route("/api/forensics", methods=["POST"])
def forensics_api():

    uploaded = request.files.get("file")

    if uploaded is None or not uploaded.filename:
        return jsonify({
            "success": False,
            "error": "No image or PDF file supplied."
        }), 400

    filename = secure_filename(uploaded.filename)

    if not filename:
        return jsonify({
            "success": False,
            "error": "Invalid file name."
        }), 400

    extension = os.path.splitext(filename)[1].lower()

    if extension not in {
        ".jpg", ".jpeg", ".png", ".webp", ".tif", ".tiff", ".bmp", ".pdf"
    }:
        return jsonify({
            "success": False,
            "error": "Unsupported file type. Upload an image or PDF."
        }), 400

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=extension
        ) as temp:
            temp_path = temp.name
            uploaded.save(temp_path)

        result = analyze_file(temp_path)

        return jsonify({
            "success": True,
            "result": result
        })

    except Exception as exc:
        return jsonify({
            "success": False,
            "error": f"Forensic analysis failed: {str(exc)}"
        }), 500

    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)


# ============================================================
# KNOWLEDGE EXPLORER API
# ============================================================

@app.route("/api/knowledge")
def knowledge_api():

    knowledge_list = []


    for key, threat in THREAT_KNOWLEDGE.items():

        knowledge_list.append({

            "id": key,

            "name": threat.get(
                "name",
                key.replace("_", " ").title()
            ),

            "category": threat.get(
                "category",
                "Unknown"
            ),

            "severity": threat.get(
                "severity",
                "UNKNOWN"
            ),

            "mitre_id": threat.get(
                "mitre_id",
                "N/A"
            ),

            "mitre_name": threat.get(
                "mitre_name",
                "N/A"
            ),

            "description": threat.get(
                "description",
                "No description available."
            ),

            "indicators": threat.get(
                "indicators",
                []
            ),

            "actions": threat.get(
                "actions",
                []
            )

        })


    return jsonify({
        "success": True,
        "count": len(knowledge_list),
        "knowledge": knowledge_list
    })


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/health")
def health():

    return {

        "status": "online",

        "assistant": "SHERLOCK",

        "message":
            "Sherlock cybersecurity reasoning engine is running.",

        "knowledge_entries":
            len(THREAT_KNOWLEDGE)

    }


# ============================================================
# RUN SERVER
# ============================================================

if __name__ == "__main__":

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )