from flask import Blueprint, jsonify

produtos_bp = Blueprint('produtos', __name__)

@produtos_bp.route("/", methods=["GET"])
def listar_produtos():
    return jsonify({"produtos": ["Produto A", "Produto B", "Produto C"]})

@produtos_bp.route("/<int:id>", methods=["GET"])
def obter_produto(id):
    return jsonify({"produto": f"Produto com ID {id}"})

