import asyncio
import queue
import uvicorn

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from classes.FlowClassifier import FlowClassifier

classifier = 'models/classifier/xgb_clf_multiclass.pkl'
anomaly_detector = 'models/anomaly_detector/isolation_forest.pkl'

ids = FlowClassifier(classifier_path=classifier, anomaly_detector=anomaly_detector)
ids.start_capture()

app = FastAPI()

html = """
<!DOCTYPE html>
<html>
    <head>
        <title>Chat</title>
    </head>
    <body>
        <h1>WebSocket RT-IDS</h1>
        </ul>
        <script>
            var ws = new WebSocket("ws://localhost:8000/ws");
            ws.onopen = function(event) {
                console.log('Connected to WebSocket');
            };
            ws.onmessage = function(event) {
                console.log(event.data)
            };
            ws.onclose = function(event) {
                console.log('WebSocket connection closed');
            };
        </script>
    </body>
</html>
"""

@app.get("/")
async def get():
    return HTMLResponse(html)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            try:
                data = ids.packet_queue.get_nowait()
                await websocket.send_json(f"Message text was: {data}")
            except queue.Empty:
                await asyncio.sleep(0.1)
    except WebSocketDisconnect:
        print("Client disconnected")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
