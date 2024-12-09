from flask import Blueprint, jsonify

usuarios_bp = Blueprint('usuarios', __name__)

@usuarios_bp.route("/", methods=["GET"])
def listar_usuarios():
    return jsonify({"usuarios": ["João", "Maria", "Ana"]})

@usuarios_bp.route("/<int:id>", methods=["GET"])
def obter_usuario(id):
    return jsonify({"usuario": f"Usuário com ID {id}"})