from fastapi import FastAPI

app = FastAPI(title='Scan SSL/TLS', version='1.0')

@app.get('/teste')
def hello_world():
    objeto = {
        'green': 'Deu certo'
    }
    return objeto
