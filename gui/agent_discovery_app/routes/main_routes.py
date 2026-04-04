from flask import Blueprint, jsonify, render_template, request

from services.environment_service import detect_os
from services.scope_service import load_scope, save_scope
from services.output_service import list_outputs
from services.job_service import (
    start_agent_job,
    start_discovery_job,
    get_job_status,
)

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    return render_template("index.html")


@main_bp.route("/api/environment", methods=["GET"])
def api_environment():
    return jsonify(detect_os())


@main_bp.route("/api/scope", methods=["GET"])
def api_get_scope():
    return jsonify(load_scope())


@main_bp.route("/api/scope", methods=["POST"])
def api_save_scope():
    data = request.get_json(force=True)

    try:
        scope_data = {
            "authorized_networks": data.get("authorized_networks", ["*"]),
            "authorized_interfaces": data.get("authorized_interfaces", ["*"]),
            "max_hosts_per_subnet": int(data.get("max_hosts_per_subnet", 1024)),
            "private_only": bool(data.get("private_only", True)),
        }

        saved_scope = save_scope(scope_data)

        return jsonify({
            "success": True,
            "scope": saved_scope
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400


@main_bp.route("/api/job-status", methods=["GET"])
def api_job_status():
    return jsonify(get_job_status())


@main_bp.route("/api/run-agent", methods=["POST"])
def api_run_agent():
    data = request.get_json(force=True)

    agent_type = data.get("agent_type")
    output_dir = data.get("output_dir", "outputs")

    result = start_agent_job(agent_type, output_dir)

    if not result["success"]:
        return jsonify(result), 400

    return jsonify(result)


@main_bp.route("/api/run-discovery", methods=["POST"])
def api_run_discovery():
    data = request.get_json(force=True)

    output_dir = data.get("output_dir", "outputs")

    result = start_discovery_job(output_dir)

    if not result["success"]:
        return jsonify(result), 400

    return jsonify(result)


@main_bp.route("/api/outputs", methods=["GET"])
def api_outputs():
    try:
        files = list_outputs()
        return jsonify({
            "success": True,
            "files": files
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500