import time
import threading
def atualizardadosusers(teste):

    for i in range(9999):
        for j in range(9999):
            print(i*j + 2)
    time.sleep(2)

def atualizarcustoso(param):
    threading.Thread(target=atualizardadosusers, args=(param,)).start()



