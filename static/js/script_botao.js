document.getElementById('logout-button').addEventListener('click', function() {
    fetch('/logout', {
        method: 'GET'
    }).then(response => {
        if (response.ok) {
            window.location.href = '/';
        } else {
            alert('Erro ao fazer logout.');
        }
    });
});
