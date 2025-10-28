#!/usr/bin/env python3

from flask import Flask, render_template, request
from flask_socketio import SocketIO, send, emit, join_room, leave_room

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

socketio = SocketIO(app)

# Dictionary to store users and their assigned rooms
users = {}

@app.route('/')
def index():
    return render_template('index.html')

# Handle new user joining
@socketio.on('join')
def handle_join(username):
    users[request.sid] = username  # Store username by session ID
    join_room(username)  # Each user gets their own "room"
    emit("message", f"{username} joined the chat", room=username)

# Handle user messages
@socketio.on('message')
def handle_message(data):
    username = users.get(request.sid, "Anonymous")  # Get the user's name
    emit("message", f"{username}: {data}", broadcast=True)  # Send to everyone

# Handle disconnects
@socketio.on('disconnect')
def handle_disconnect():
    username = users.pop(request.sid, "Anonymous")
    emit("message", f"{username} left the chat", broadcast=True)

if __name__ == '__main__':
    socketio.run(app, debug=True)
