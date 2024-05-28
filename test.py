from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates

app = FastAPI()
templates = Jinja2Templates(directory="./templates")

@app.get('/item/{item_name}')
def read_root(item_name: str):
    return{"item_name": item_name}

@app.get("/test")
def test(request: Request):
    return templates.TemplateResponse("index.html", {"request":request})