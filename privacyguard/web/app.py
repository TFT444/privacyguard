"""
Flask REST API + dashboard (Phase 2 and 3).

create_app() is a factory so tests can inject an in-memory database and a known
token. Endpoints:
  POST /api/event              receive a threat event (bearer-token protected)
  GET  /api/devices           device inventory
  GET  /api/alerts            alert log
  GET  /api/score             current Home Safety Score (0-100)
  POST /api/alerts/<id>/ack   acknowledge an alert
  GET  /api/stream            Server-Sent Events live feed
  GET  /                      dashboard
"""

import json
import os
import time

from flask import Flask, request, jsonify, Response, render_template

from . import db
from .safety import compute_safety_score
from .notify import send_ntfy

DAY_SECONDS = 24 * 60 * 60


def create_app(conn=None, token=None, ntfy_topic=None):
    # Deployment defaults: a real file-backed DB and env-provided token/topic.
    # Tests inject an in-memory connection and a known token explicitly.
    if conn is None:
        conn = db.connect(os.environ.get("PG_DB", "privacyguard.db"))
        db.init_db(conn)
    if token is None:
        token = os.environ.get("PG_TOKEN", "change-me")
    if ntfy_topic is None:
        ntfy_topic = os.environ.get("PG_NTFY_TOPIC")

    app = Flask(__name__)
    app.config["CONN"] = conn
    app.config["TOKEN"] = token
    app.config["NTFY_TOPIC"] = ntfy_topic

    def authorized():
        header = request.headers.get("Authorization", "")
        return header == f"Bearer {app.config['TOKEN']}"

    def current_score():
        since = time.time() - DAY_SECONDS
        return compute_safety_score(db.alerts_since(conn, since))

    @app.post("/api/event")
    def post_event():
        if not authorized():
            return jsonify(error="unauthorized"), 401
        event = request.get_json(silent=True) or {}
        db.insert_event(conn, event)
        topic = app.config["NTFY_TOPIC"]
        if topic:
            try:
                send_ntfy(event, topic)
            except Exception:  # never let a notify failure break ingestion
                pass
        return jsonify(status="stored"), 201

    @app.get("/api/devices")
    def get_devices():
        return jsonify(db.list_devices(conn))

    @app.get("/api/alerts")
    def get_alerts():
        return jsonify(db.list_alerts(conn))

    @app.get("/api/score")
    def get_score():
        return jsonify(score=current_score())

    @app.post("/api/alerts/<int:alert_id>/ack")
    def ack_alert(alert_id):
        db.acknowledge(conn, alert_id)
        return jsonify(status="acknowledged")

    @app.get("/api/stream")
    def stream():
        def gen():
            while True:
                payload = {
                    "score": current_score(),
                    "alerts": db.list_alerts(conn, limit=10),
                }
                yield f"data: {json.dumps(payload)}\n\n"
                time.sleep(2)
        return Response(gen(), mimetype="text/event-stream")

    @app.get("/")
    def dashboard():
        return render_template(
            "dashboard.html",
            score=current_score(),
            devices=db.list_devices(conn),
            alerts=db.list_alerts(conn),
        )

    return app
