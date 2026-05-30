from flask import Flask, request, jsonify
from collections import Counter
import re

app = Flask(__name__)

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})

@app.route('/wordcount', methods=['POST'])
def wordcount():
    data = request.json
    text = data.get("text", "")
    words = re.findall(r'\b\w+\b', text.lower())
    freq = Counter(words).most_common(10)
    return jsonify({"word_count": len(words), "top_words": freq})

@app.route('/palindrome', methods=['POST'])
def palindrome():
    data = request.json
    text = data.get("text", "").replace(" ", "").lower()
    return jsonify({"is_palindrome": text == text[::-1]})

@app.route('/reverse', methods=['POST'])
def reverse():
    data = request.json
    return jsonify({"reversed": data.get("text", "")[::-1]})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)