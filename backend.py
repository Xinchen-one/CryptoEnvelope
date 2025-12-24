from flask import Flask, request, jsonify, render_template
import time, os

app = Flask(__name__)

#
@app.get("/ui/chat")
def ui_chat():
    return render_template("chat.html")

@app.get("/ui/mail")
def ui_mail():
    return render_template("mail.html")
#

@app.get("/health")
def health():
    return {"ok": True, "ts": int(time.time())}

@app.route("/echo", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def echo():
    return jsonify({
        "method": request.method,
        "path": request.path,
        "args": request.args.to_dict(flat=False),
        "headers": {k: v for k, v in request.headers.items()},
        "body_text": request.get_data(as_text=True),
        "ts": int(time.time())
    })

if __name__ == "__main__":
    # 本机服务建议先监听 127.0.0.1；用 ssh -R 不需要暴露到公网
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "3000"))
    app.run(host=host, port=port, debug=False)
