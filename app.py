from flask import Flask, render_template, request
from scanner import WebSecurityScanner

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"]
        scanner = WebSecurityScanner(url)
        vulns = scanner.scan()
        return render_template("index.html", vulns=vulns, url=url)
    return render_template("index.html", vulns=None)

if __name__ == "__main__":
    app.run(debug=True)
