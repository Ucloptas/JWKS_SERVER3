import unittest
from http.server import HTTPServer
from threading import Thread
from main import MyServer
import requests
import sqlite3

class serverTester(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start the server and give it to another thread
        cls.server = HTTPServer(('localhost', 8080), MyServer)
        cls.thread = Thread(target=cls.server.serve_forever)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()

    def test_auth(self):  # Ensures that requests reach OK state
        response = requests.post("http://localhost:8080/auth",
                                headers={"Content-Type": "application/json"},
                                json={"username": "bob",})
        self.assertEqual(response.status_code, 200)

    def test_wellKnown(self):
        response = requests.get("http://localhost:8080/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)

    # Testing things that are not allowed (PATCH, DELETE, HEAD to auth endpoint)
    def test_patch_notAllowed_auth(self):
        response = requests.patch("http://localhost:8080/auth")
        self.assertEqual(response.status_code, 405)

    def test_delete_notAllowed_auth(self):
        response = requests.delete("http://localhost:8080/auth")
        self.assertEqual(response.status_code, 405)

    def test_head_notAllowed_auth(self):
        response = requests.head("http://localhost:8080/auth")
        self.assertEqual(response.status_code, 405)

    # Testing things that are not allowed (PATCH, DELETE, HEAD to well-known endpoint)
    def test_patch_notAllowed_wellKnown(self):
        response = requests.patch("http://localhost:8080/.well-known/jwks.json")
        self.assertEqual(response.status_code, 405)

    def test_delete_notAllowed_wellKnown(self):
        response = requests.delete("http://localhost:8080/.well-known/jwks.json")
        self.assertEqual(response.status_code, 405)

    def test_head_notAllowed_wellKnown(self):
        response = requests.head("http://localhost:8080/.well-known/jwks.json")
        self.assertEqual(response.status_code, 405)

