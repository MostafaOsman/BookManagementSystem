import unittest
from app import app, db, User, Book
from flask_jwt_extended import create_access_token

class APITestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'  # Use in-memory database for tests
        app.config['JWT_SECRET_KEY'] = 'testing'  # Secret key for tests
        cls.client = app.test_client()
        with app.app_context():
            db.create_all()

    @classmethod
    def tearDownClass(cls):
        with app.app_context():
            db.drop_all()

    def setUp(self):
        # Clear database and add a sample user
        with app.app_context():
            db.session.query(User).delete()
            db.session.query(Book).delete()
            user = User(username='testuser')
            user.set_password('testpassword')
            db.session.add(user)
            db.session.commit()

    def login(self, username='testuser', password='testpassword'):
        # Helper function to get access token
        response = self.client.post('/login', json={
            'username': username,
            'password': password
        })
        return response.get_json()['access_token']

    def test_register_user(self):
        response = self.client.post('/register', json={
            'username': 'newuser',
            'password': 'newpassword'
        })
        self.assertEqual(response.status_code, 201)
        self.assertIn('msg', response.get_json())

    def test_login_user(self):
        response = self.client.post('/login', json={
            'username': 'testuser',
            'password': 'testpassword'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn('access_token', response.get_json())
        self.assertIn('refresh_token', response.get_json())

    def test_refresh_token(self):
        # Log in to get both access and refresh tokens
        response = self.client.post('/login', json={
            'username': 'testuser',
            'password': 'testpassword'
        })
        refresh_token = response.get_json()['refresh_token']  # Get the refresh token

        # Use the refresh token to request a new access token
        headers = {'Authorization': f'Bearer {refresh_token}'}
        response = self.client.post('/refresh', headers=headers)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn('access_token', response.get_json())  # Verify we received a new access token


    def test_create_book(self):
        access_token = self.login()
        headers = {'Authorization': f'Bearer {access_token}'}
        response = self.client.post('/books', headers=headers, json={
            'title': 'New Book',
            'author': 'Author Name',
            'isbn': '1234567890123',
            'genre': 'Fiction',
            'publication_date': '2023-10-01',
            'description': 'A new book description'
        })
        self.assertEqual(response.status_code, 201)
        self.assertIn('title', response.get_json())

    def test_list_books(self):
        access_token = self.login()
        headers = {'Authorization': f'Bearer {access_token}'}
        # First, create a book
        self.client.post('/books', headers=headers, json={
            'title': 'New Book',
            'author': 'Author Name',
            'isbn': '1234567890123'
        })
        # Then, list books
        response = self.client.get('/books', headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertGreater(len(response.get_json()), 0)

    def test_get_book(self):
        access_token = self.login()
        headers = {'Authorization': f'Bearer {access_token}'}
        # First, create a book
        book_response = self.client.post('/books', headers=headers, json={
            'title': 'Book to Retrieve',
            'author': 'Author Name',
            'isbn': '1234567890123'
        })
        book_id = book_response.get_json()['id']
        # Then, retrieve the book by ID
        response = self.client.get(f'/books/{book_id}', headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['title'], 'Book to Retrieve')

    def test_update_book(self):
        access_token = self.login()
        headers = {'Authorization': f'Bearer {access_token}'}
        # First, create a book
        book_response = self.client.post('/books', headers=headers, json={
            'title': 'Original Title',
            'author': 'Author Name',
            'isbn': '1234567890123'
        })
        book_id = book_response.get_json()['id']
        # Update the book
        response = self.client.put(f'/books/{book_id}', headers=headers, json={
            'title': 'Updated Title'
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['title'], 'Updated Title')

    def test_delete_book(self):
        access_token = self.login()
        headers = {'Authorization': f'Bearer {access_token}'}
        # First, create a book
        book_response = self.client.post('/books', headers=headers, json={
            'title': 'Book to Delete',
            'author': 'Author Name',
            'isbn': '1234567890123'
        })
        book_id = book_response.get_json()['id']
        # Delete the book
        response = self.client.delete(f'/books/{book_id}', headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn('message', response.get_json())
        # Confirm deletion
        get_response = self.client.get(f'/books/{book_id}', headers=headers)
        self.assertEqual(get_response.status_code, 404)
        
    def test_logout(self):
        # Log in to get an access token
        access_token = self.login()
        headers = {'Authorization': f'Bearer {access_token}'}

        # Call the logout endpoint to invalidate the access token
        response = self.client.post('/logout', headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn('msg', response.get_json())
        self.assertEqual(response.get_json()['msg'], 'Logout successful')

        # Try accessing a protected route with the same token after logout
        response = self.client.get('/books', headers=headers)
        self.assertEqual(response.status_code, 401)  # Access should be denied    

if __name__ == '__main__':
    unittest.main()
