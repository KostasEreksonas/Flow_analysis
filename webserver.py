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
        <table>
            <thead>
                <tr>Flow ID</tr>
                <tr>Source</tr>
                <tr>Destination</tr>
                <tr>Protocol</tr>
            </thead>
            <tbody id=flow>
            </tbody>
        </table>
        <script>
            var ws = new WebSocket("ws://localhost:8000/ws");
            ws.onopen = function(event) {
                console.log('Connected to WebSocket');
            };
            ws.onmessage = function(event) {
                data = JSON.parse(event.data);
                let table = document.getElementById("flow");
                let row = table.insertRow();
                let flow_id = row.insertCell(0);
                let source = row.insertCell(1);
                let destination = row.insertCell(2);
                let protocol = row.insertCell(3);
                flow_id.innerHTML = data['flow_id']
                source.innerHTML = `${data['original_flow_key'][0]}:${data['original_flow_key'][2]}`
                destination.innerHTML = `${data['original_flow_key'][1]}:${data['original_flow_key'][3]}`
                protocol.innerHTML = data['original_flow_key'][4]
                console.log(data['original_flow_key'][0])
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
                await websocket.send_json(data)
            except queue.Empty:
                await asyncio.sleep(0.1)
    except WebSocketDisconnect:
        print("Client disconnected")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
