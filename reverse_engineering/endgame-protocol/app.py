from fastapi import FastAPI
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

FLAG = "DSCCTF{th3_r34l_3ndg4m3_w45_th3_pr0t0c0l_2026}"

def snap_transform(s):
    out = []
    for i, c in enumerate(s):
        out.append(chr((ord(c) ^ (i % 42)) + 1))
    return ''.join(out)

@app.get("/", response_class=HTMLResponse)
def index():
    return open("templates/index.html").read()

@app.get("/snap")
def snap():
    transformed = snap_transform(FLAG)
    return PlainTextResponse(transformed)
