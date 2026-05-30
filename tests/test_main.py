import sys
sys.path.append('.')
from app.main import app
import json

client = app.test_client()

def test_health():
    res = client.get('/health')
    assert res.status_code == 200

def test_wordcount():
    res = client.post('/wordcount',
        data=json.dumps({"text": "hello world hello"}),
        content_type='application/json')
    data = json.loads(res.data)
    assert data['word_count'] == 3

def test_palindrome_true():
    res = client.post('/palindrome',
        data=json.dumps({"text": "racecar"}),
        content_type='application/json')
    data = json.loads(res.data)
    assert data['is_palindrome'] == True

def test_palindrome_false():
    res = client.post('/palindrome',
        data=json.dumps({"text": "hello"}),
        content_type='application/json')
    data = json.loads(res.data)
    assert data['is_palindrome'] == False

def test_reverse():
    res = client.post('/reverse',
        data=json.dumps({"text": "hello"}),
        content_type='application/json')
    data = json.loads(res.data)
    assert data['reversed'] == "olleh"