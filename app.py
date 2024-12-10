from flask import *
import dao
import atualizar as atual
import dataanalise
import os
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta
from flask import session
import os
from models import Produto as Produto
from models import Usuario as Usuario
from flask_sqlalchemy import SQLAlchemy
import pandas as pd
import plotly.express as px
from flask import render_template


app = Flask(__name__)
app.secret_key = 'xcsdKJAH_Sd56$'

#blueprints
from rotas.usuarios import  usuarios_bp
from rotas.produtos import  produtos_bp

app.register_blueprint(usuarios_bp, url_prefix="/usuariosx")
app.register_blueprint(produtos_bp, url_prefix="/produtosx")

app.config["JWT_SECRET_KEY"] = 'xcsdKJAH_Sd56$'
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(seconds=20)
jwt = JWTManager(app)


UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

arquivo_csv = 'vendas_grande.csv'
db = SQLAlchemy()


@app.route('/upload', methods=['GET','POST'])
def uploadArquivo():

    if request.method == 'GET':
        return render_template('uploadarquivo.html')

    if 'file' not in request.files:
        return 'nao mandou nenhum arquivo'

    file = request.files['file']

    if file.filename == '':
        return 'sem nome de arquivo ou nenhum arquivo foi selecionado p envio'

    if file:
        nomeArquivo = file.filename
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], nomeArquivo))
        return f'deu certo: arquivo {nomeArquivo} salvo com sucesso', 200


@app.route('/')
def home():

    return render_template('index2.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('loginUser', None)  # Remove o loginUser da sessão
    session.pop('tipoUser', None)
    return jsonify({"message": "Logout bem-sucedido!"}), 200


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    usuario = Usuario.query.filter_by(loginUser=data['loginUser']).first()
    if usuario and usuario.senha == data['senha']:
        session['loginUser'] = usuario.loginUser
        session['tipoUser'] = usuario.tipoUser
        return jsonify({"message": "Login bem-sucedido!"}), 200
    return jsonify({"message": "Credenciais inválidas"}), 401


def verificar_login():
    if 'loginUser' not in session:
        return jsonify({"message": "Usuário não autenticado"}), 401
    return None

@app.route('/produtos', methods=['POST'])
def inserir_produto():
    auth_check = verificar_login()
    if auth_check:
        return auth_check  # Se não estiver logado, retorna erro de não autenticado

    data = request.get_json()
    produto = Produto(nome=data['nome'], loginUser=session['loginUser'], qtde=data['qtde'], preco=data['preco'])
    db.session.add(produto)
    db.session.commit()
    return jsonify({"message": "Produto inserido com sucesso!"}), 201


@app.route('/atualizardados', methods=['POST'])
def atualizar():
    atual.atualizarcustoso('teste')
    return render_template('index2.html')

@app.route('/atualizaruser', methods=['POST'])
def atualizaruser():
    pessoas = {'nome':'rene'}
    return jsonify(pessoas)


@app.route('/exibirgraficoprodutos')
def exibirgrafProds():
    caminho_arquivo = os.path.join(UPLOAD_FOLDER, arquivo_csv)

    fig = dataanalise.gerarGrafProdutos(caminho_arquivo)
    return render_template('grafprodutos.html', plot=fig.to_html())


@app.route('/exibirpagCadastro')
def exibirPagCadastro():
    if 'login_user' in session:

        return render_template('cadastrarprod.html', user=session['login_user'])
    else:

        return render_template('index2.html', msg='Login necessário')

@app.route('/produtos', methods=['GET'])
def listar_produtos():
    # Verifica se o usuário está logado
    auth_check = verificar_login()
    if auth_check:
        return auth_check  # Retorna erro se o usuário não estiver autenticado

    # Consulta todos os produtos no banco de dados
    produtos = Produto.query.all()

    # Formata os produtos em JSON
    produtos_json = [
        {
            "id": produto.id,
            "nome": produto.nome,
            "loginUser": produto.loginUser,
            "qtde": produto.qtde,
            "preco": produto.preco,
        }
        for produto in produtos
    ]

    return jsonify(produtos_json), 200


@app.route('/exibirPagComentario')
def exibirPagComent():
    return render_template('inserirmsg.html')

@app.route('/comentario/inserir', methods=['POST'])
def inserirmsgdatabase():
    coment = request.form.get('mensagem')
    print(coment + " - " + session['login_user'])
    if dao.insert_comentario(session['login_user'], coment, dao.conectardb()):
        return 'inseriu com sucesso!' #crie uma pag para isso
    else:
        return render_template(home.html, user=session['login_user'])

#API rest

@app.route('/inserir', methods=['POST'])
def inserir_usuario():

    if not request.json:
        abort(400, description="Dados inválidos")

    login = request.json["login"]
    senha = request.json["senha"]

    if dao.inserirusuario(login, senha):
        return jsonify(dao.listarpessoas(1)), 200
    else:
        abort(400, description="Usuário com login já cadastrado ")

@app.route('/listar', methods=['GET'])
def get_todos():
    return jsonify(dao.listarpessoas(1)), 200

#aqui eu usei uma forma possível mas não recomendada: mandei user e senha via post usando o HTTP (pode ser interceptado)
@app.route('/listarusuarios/externo', methods=['POST'])
def get_todos_externo():
    if not request.json:
        abort(400, description="Dados inválidos")#enviar um objeto response informando erro

    login = request.json["login"]
    senha = request.json["senha"]
    print(login)
    if dao.verificarlogin(login, senha, dao.conectardb()):
        return jsonify(dao.listarpessoas(1)), 200
    else:
        return abort(401,'Usuário ou senha inválidos')


@app.route('/obter/<string:login>', methods=['GET'])
def get_usuario(login):
    user = dao.buscar_pessoa(login)
    if len(user) == 0:
        abort(404, description="Tarefa não encontrada")
    return jsonify(user), 200


#---------- autenticaçao com jwt------------------------

@app.route('/login/externo', methods=['POST'])
def login_externo():
    login = request.json['login']
    senha = request.json['senha']
    print(login)

    if dao.verificarlogin(login, senha, dao.conectardb()):
        token = create_access_token(identity=login)
        return jsonify(access_token=token), 200
    else:
        abort(401, description="Usuário ou senha inválidos")
        #ou
        #return jsonify({"message": "Usuário ou senha inválidos"}), 401


@app.route('/protegido/obter/<string:login>', methods=['GET'])
@jwt_required()
def get_usuario_protegido(login):
    usuario_logado = get_jwt_identity()
    print(usuario_logado)
    user = dao.buscar_pessoa(login)
    if len(user) == 0:
        abort(404, description="usuário não encontrado")
    return jsonify(user), 200


@app.route('/protegido/listarusuarios/externo', methods=['GET'])
@jwt_required()
def listar_usuarios_externo():
    usuario_logado = get_jwt_identity()
    print(usuario_logado)
    return jsonify(dao.listarpessoas(1)), 200



if __name__ == '__main__':
    app.run(debug=True)

    #certificado = os.path.join('ssl', 'certificado.pem')
    #chave = os.path.join('ssl', 'chave.pem')
    #app.run(ssl_context=(certificado, chave), debug=True )


'''
instalei 
como estamos usando um certificado SSL autoassinado, o chrome e os outros navegadores 
não consideram certificados autoassinados confiáveis (nossa gambiarra local).
 Lembrem que eles não foram emitidos por uma autoridade certificadora reconhecida (usamos o openssl).
 se quise usar um, procure o Let's Encrypt (gratuito).
'''
