from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Produto(db.Model):
    __tablename__ = 'produtos'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    loginUser = db.Column(db.String(50), db.ForeignKey('usuarios.loginUser'), nullable=False)
    qtde = db.Column(db.Integer, nullable=False)
    preco = db.Column(db.Float, nullable=False)

class Usuario(db.Model):
    __tablename__ = 'usuarios'
    id = db.Column(db.Integer, primary_key=True)
    loginUser = db.Column(db.String(50), unique=True, nullable=False)
    senha = db.Column(db.String(100), nullable=False)
    tipoUser = db.Column(db.String(10), nullable=False)  # 'super' ou 'normal'
    produtos = db.relationship('Produto', backref='usuario', lazy=True)


