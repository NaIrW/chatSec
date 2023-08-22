from fastapi import FastAPI, Request
from db import DB
from fastapi.responses import FileResponse
import json
from chat import handleChat


skdb = DB('api.sk')
app = FastAPI()


@app.post('/chatSecret')
async def chatSecret(request: Request):
    try:
        item_dict = await request.json()
    except json.decoder.JSONDecodeError:
        return {'msg': 'Error'}
    return handleChat(item_dict)
