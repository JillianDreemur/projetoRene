const botao = document.getElementById('atualizarData');
const texto = document.getElementById('saidatexto');

function atualizar(){
            preventDefault();
            fetch('/atualizaruser', {
                method: 'POST'
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Erro na resposta do servidor');
                }
                return response.json();
            })
            .then(data => {
                texto.textContent = data.nome;
            })
            .catch(error => {
                alert('errooooo');
            });

}

botao.addEventListener('click', atualizar());

