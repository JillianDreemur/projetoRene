#pip install kivy
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.network.urlrequest import UrlRequest
from kivy.uix.label import Label
from kivy.core.window import Window
from kivy.utils import get_color_from_hex
from kivy.uix.scrollview import ScrollView
import json

class MainApp(App):
    global token
    token = ''

    def logar(self, *args):
        url = 'http://127.0.0.1:5000/login/externo'
        headers = {'Content-Type': 'application/json'}

        body = {'login': 'rene', 'senha':'123'}
        UrlRequest(url, req_headers=headers, req_body=json.dumps(body), method='POST',
                   on_success=self.pegar_token, on_error=self.on_error)

    def pegar_token(self, request, response):
        global token
        token = response['access_token']
        print(token)
        self.list_layout.clear_widgets()
        self.list_layout.add_widget(
            Label(text=f"\n\nLogado", font_size=28, color=get_color_from_hex('#FFFFFF')))

    def send_request2(self, *args):
        url = 'http://127.0.0.1:5000/listarusuarios/externo'
        headers = {'Content-Type': 'application/json'}

        body = {'login': 'rene', 'senha':'1234'}
        UrlRequest(url, req_headers=headers, req_body=json.dumps(body), method='POST',
                   on_success=self.on_success, on_error=self.on_error, on_failure=self.caso_falhe)


    def caso_falhe(self,request, response):
        print(response)
        self.list_layout.clear_widgets()
        self.list_layout.add_widget(
            Label(text=f"\n\nUsuário ou senha inválidos", font_size=28, color=get_color_from_hex('#FFFFFF')))

    def send_request(self, *args):
        global token
        token_local = f'Bearer {token}'
        url = 'http://127.0.0.1:5000/protegido/listarusuarios/externo'
        headers = {'Authorization' : token_local}
        UrlRequest(url, req_headers=headers, method='GET',
                   on_success=self.on_success, on_error=self.on_error, on_failure=self.on_falilure)

    def on_success(self, request, response):
        print(response)
        self.list_layout.clear_widgets()
        self.list_layout.add_widget(Label(text=f""))
        for item in response:

            self.list_layout.add_widget(
                Label(text=f"Login: {item['login']}", font_size=20, color=get_color_from_hex('#FFFFFF')))
            self.list_layout.add_widget(
                Label(text=f"Comentário: {item['comentario']}", font_size=20, color=get_color_from_hex('#FFFFFF')))
            self.list_layout.add_widget(Label(text=f""))

    def on_falilure(self,request, response):
        print(response)
        self.list_layout.clear_widgets()
        self.list_layout.add_widget(
            Label(text=f"\n\nUsuário não logado", font_size=28, color=get_color_from_hex('#FFFFFF')))

    def on_error(self, req, error):
        print(error)
        self.list_layout.clear_widgets()
        self.list_layout.add_widget(Label(text="ERROOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO"))

    def build(self):
        Window.size = (400, 600)

        main_layout = BoxLayout(orientation='vertical', padding=20)
        scrollview = ScrollView()

        botao_logar = Button(text="Logar", size_hint=(0.3, 0.1), size=(50, 50),
                                pos_hint={'center_x': 0.5, 'center_y': 0.5})
        botao_logar.bind(on_press=self.logar)

        bota_listar = Button(text="Listar Usuários", size_hint=(0.3, 0.1), size=(50, 50),
                                pos_hint={'center_x': 0.5, 'center_y': 0.5})
        bota_listar.bind(on_press=self.send_request)#associar um método para um botao

        self.list_layout = BoxLayout(orientation='vertical', size_hint_y=None, spacing=30)
        self.list_layout.bind(minimum_height=self.list_layout.setter('height'))

        scrollview.add_widget(self.list_layout)

        main_layout.add_widget(botao_logar)
        main_layout.add_widget(bota_listar)
        main_layout.add_widget(scrollview)

        return main_layout

if __name__ == '__main__':
    MainApp().run()
