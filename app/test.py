from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates

app = FastAPI()
templates = Jinja2Templates(directory="./templates")

@app.get('/item/{item_name}')
def read_root(item_name: str):
    return{"item_name": item_name}  

@app.get("/test/{test}")
def test(request: Request, test: int):
    return templates.TemplateResponse("index.html", {"request":request, "test": test})

@app.get("/jeo/{name}/{number}")
def test(request: Request, name: str, number: int):
    return templates.TemplateResponse("index.html", {"request":request, "name": name, "number":number})

@app.get("/home")
def test(request: Request):
    return templates.TemplateResponse("home.html", {"request":request})