"""
Minimal Flask OAuth2 simulation server.
"""

import json
import time
from flask import Flask, request, jsonify, g
from benchmark.config import JWT_PAYLOAD


def create_app(jwt_engine_module, algo_name, algo_config, keys):
    app = Flask(__name__)
    app.config['TESTING'] = True

    users_db = {}
    tasks_db = {}
    task_counter = [0]

    @app.before_request
    def before():
        g.start_time = time.perf_counter_ns()
        g.request_header_size = len(json.dumps(dict(request.headers)).encode())

    @app.after_request
    def after(response):
        elapsed = time.perf_counter_ns() - g.start_time
        response.headers['X-Response-Time-Ms'] = str(elapsed / 1_000_000)
        response.headers['X-Request-Header-Size'] = str(g.request_header_size)
        response.headers['X-Response-Body-Size'] = str(len(response.get_data()))
        return response

    def require_auth(f):
        from functools import wraps
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = request.headers.get("Authorization", "").replace("Bearer ", "")
            valid, ver_time = jwt_engine_module.verify_token(algo_name, algo_config, keys, token)
            if not valid:
                return jsonify({"error": "Unauthorized"}), 401
            g.ver_time_ms = ver_time
            return f(*args, **kwargs)
        return wrapper

    @app.route('/auth/register', methods=['POST'])
    def register():
        data = request.get_json() or {}
        email = data.get("email")
        if email in users_db:
            return jsonify({"error": "exists"}), 400
        users_db[email] = {"password": data.get("password")}
        payload = dict(JWT_PAYLOAD)
        payload["sub"] = email
        token, t = jwt_engine_module.generate_token(algo_name, algo_config, keys, payload)
        return jsonify({"token": token, "gen_time_ms": t}), 201

    @app.route('/auth/login', methods=['POST'])
    def login():
        data = request.get_json() or {}
        email = data.get("email")
        if email not in users_db or users_db[email]["password"] != data.get("password"):
            return jsonify({"error": "Invalid"}), 401
        payload = dict(JWT_PAYLOAD)
        payload["sub"] = email
        token, t = jwt_engine_module.generate_token(algo_name, algo_config, keys, payload)
        return jsonify({"token": token, "gen_time_ms": t}), 200

    @app.route('/auth/login-bad', methods=['POST'])
    def login_bad():
        return jsonify({"error": "Invalid"}), 401

    @app.route('/tasks', methods=['POST'])
    @require_auth
    def create_task():
        task_counter[0] += 1
        tid = task_counter[0]
        tasks_db[tid] = {"id": tid, "title": "task"}
        return jsonify(tasks_db[tid]), 201

    @app.route('/tasks', methods=['GET'])
    @require_auth
    def get_tasks():
        return jsonify(list(tasks_db.values()))

    @app.route('/tasks/<int:tid>', methods=['PUT'])
    @require_auth
    def update_task(tid):
        if tid not in tasks_db:
            return jsonify({"error": "Not found"}), 404
        tasks_db[tid]["title"] = "updated"
        return jsonify(tasks_db[tid])

    @app.route('/tasks/<int:tid>', methods=['DELETE'])
    @require_auth
    def delete_task(tid):
        tasks_db.pop(tid, None)
        return jsonify({"message": "Deleted"})

    return app
