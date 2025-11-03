import asyncio
import queue
import uvicorn

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from classes.FlowClassifier import FlowClassifier

classifier = 'models/classifier/xgb_clf_multiclass.pkl'
anomaly_detector = 'models/anomaly_detector/isolation_forest.pkl'

ids = FlowClassifier(classifier_path=classifier, anomaly_detector=anomaly_detector)
ids.start_capture()

app = FastAPI()

# Mount the js directory to serve static files
app.mount("/js", StaticFiles(directory="js"), name="js")

@app.get("/")
async def get():
    with open("index.html", "r") as f:
        html = f.read()
    return HTMLResponse(html)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            try:
                data = ids.packet_queue.get_nowait()
                await websocket.send_json(data)
            except queue.Empty:
                await asyncio.sleep(0.1)
    except WebSocketDisconnect:
        print("Client disconnected")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
