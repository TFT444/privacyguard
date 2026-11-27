"""
Flask REST API + dashboard (Phase 2 and 3).

Endpoints (planned):
  POST /api/event    receive a threat event (bearer-token protected)
  GET  /api/devices  device inventory
  GET  /api/alerts   alert log
  GET  /api/score    current Home Safety Score (0-100)
  GET  /            dashboard (Jinja2 + Server-Sent Events)

TODO (Phase 2/3): create_app() factory, routes, SSE stream, Safety Score.
"""
