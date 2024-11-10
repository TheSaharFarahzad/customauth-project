from flask import Flask, jsonify, request

app = Flask(__name__)

# Simple in-memory store for tasks (usually would be a database)
tasks = []


@app.route("/")
def home():
    return "Welcome to the ToDo API! Available routes: /tasks [GET, POST]"


@app.route("/tasks", methods=["GET"])
def get_tasks():
    return jsonify(tasks)


@app.route("/tasks", methods=["POST"])
def add_task():
    task_data = request.get_json()
    task = {
        "id": len(tasks) + 1,
        "title": task_data.get("title"),
        "done": task_data.get("done", False),
    }
    tasks.append(task)
    return jsonify(task), 201


@app.route("/tasks/<int:task_id>", methods=["PUT"])
def update_task(task_id):
    task_data = request.get_json()
    task = next((task for task in tasks if task["id"] == task_id), None)
    if task:
        task["title"] = task_data.get("title", task["title"])
        task["done"] = task_data.get("done", task["done"])
        return jsonify(task)
    return jsonify({"error": "Task not found"}), 404


@app.route("/tasks/<int:task_id>", methods=["DELETE"])
def delete_task(task_id):
    global tasks
    tasks = [task for task in tasks if task["id"] != task_id]
    return jsonify({"message": "Task deleted"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
