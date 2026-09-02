from flask import Flask, request, jsonify, render_template
from analyzer import analyze

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_email():
    data = request.json
    raw_email = data.get('email', '')
    if not raw_email:
        return jsonify({'error': 'No email provided'}), 400
    result = analyze(raw_email)
    # make body serializable
    body = result.get('body')
    if isinstance(body, bytes):
        try:
            result['body'] = body.decode('utf-8', errors='replace')
        except:
            result['body'] = ''
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True, port=5000)