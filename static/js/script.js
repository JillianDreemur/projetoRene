function verificar(){
    var login = document.getElementById('login').value
    var senha = document.getElementById('senha').value
    var paragrafo = document.getElementById('mensagem')
    var botao = document.getElementById('botaoenviar')

    if(login == "" || senha == ""){
        paragrafo.textContent = "Campo vazio";
        paragrafo.style.color = "red";
        botao.type = "reset"
    }else{
        botao.type = "submit"
    }

}
