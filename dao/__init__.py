import psycopg2
from psycopg2.extras import RealDictCursor

def conectardb():
    con = psycopg2.connect(
        #host='dpg-crl0ao3qf0us73cmdlu0-a.oregon-postgres.render.com',
        #database='p4bcc',
        #user='p4bcc_user',
        #password='UZxYdHDJHcpAgxjp7hTtP033nhbqGWxo'
        host='localhost',
        database='bdMari',
        user='postgres',
        password='123456'
    )
    return con

def verificarlogin(nome, senha, conexao):

    cur = conexao.cursor()
    cur.execute(f"SELECT count(*) FROM usuario WHERE login = '{nome}' AND senha = '{senha}'")
    recset = cur.fetchall()

    cur.close()
    conexao.close()

    if recset[0][0] == 1:
        return True
    else:
        return False

def insert_comentario(login, comentario, conexao):

    cur = conexao.cursor()
    exito = False
    try:
        #mudar nome da tabela
        sql = (f"UPDATE usuario SET comentario = '{comentario}' where login = '{login}'")
        cur.execute(sql)
    except psycopg2.IntegrityError:
        conexao.rollback()
        exito = False
    else:
        conexao.commit()
        exito = True

    cur.close()
    conexao.close()
    return exito

def inserirusuario(login, senha):
    conexao = conectardb()
    cur = conexao.cursor()
    exito = False
    try:
        sql = f"INSERT INTO usuario (login, senha) VALUES ('{login}', '{senha}')"
        cur.execute(sql)
    except psycopg2.IntegrityError:
        conexao.rollback()
        exito = False
    else:
        conexao.commit()
        exito = True

    conexao.close()
    return exito

def listarpessoas(opcao):
    conexao = conectardb()
    if opcao == 0:
        cur = conexao.cursor()
    else:
        cur = conexao.cursor(cursor_factory=RealDictCursor)
    cur.execute(f"SELECT * FROM usuario")
    recset = cur.fetchall()
    conexao.close()

    return recset


def buscar_pessoa(login):
    conexao = conectardb()
    cur = conexao.cursor()
    cur.execute(f"SELECT * FROM usuario where login= '{login}' ")
    recset = cur.fetchall()
    conexao.close()

    return recset


#inserirusuario("jose","123")
#print(listarpessoas(1))
#insert_comentario('rene','mengoooo',conectardb())
#print(buscar_pessoa("rene"))