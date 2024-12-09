import plotly.express as px
import dao
import pandas as pd

def gerarGrafProdutos(path):
    #dao.listar_produto(id)
    #pandas trabalha com um tipo de dado chamado dataframe
    #importei os dados
    df = pd.read_csv(path)

    #converter para datetime
    df['data'] = pd.to_datetime(df['data'])

    df['mes'] = df['data'].dt.to_period('M').astype(str)

    df_agrupado = df.groupby(['mes', 'nome_produto'])['quantidade_vendida'].sum().reset_index()

    fig = px.line(
        df_agrupado,
        x='mes',
        y='quantidade_vendida',
        color='nome_produto',
        title='Evolução das Vendas por Produto',
        labels={'data': 'Data', 'quantidade_vendida': 'Quantidade Vendida'},
    )
    return fig

