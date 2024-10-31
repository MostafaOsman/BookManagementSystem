import os 
import logging
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Date, CheckConstraint
from flask_jwt_extended import (JWTManager, create_access_token, create_refresh_token, jwt_required,
                                get_jwt_identity, get_jwt)
from flasgger import Swagger
from werkzeug.security import generate_password_hash, check_password_hash

# Configure logging
logging.basicConfig(level=logging.INFO)
_logger = logging.getLogger(__name__)

JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///books.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 300  # 5 minutes
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = 86400  # 1 day

db = SQLAlchemy(app)
jwt = JWTManager(app)
swagger = Swagger(app)

# Blocklist as a dictionary to store expiration time
blocklist = {}

# Cleanup function to remove expired tokens from the blocklist
def cleanup_expired_tokens():
  current_time = datetime.now(timezone.utc)
  expired_tokens = [jti for jti, exp in blocklist.items() if exp < current_time]
  for jti in expired_tokens:
      del blocklist[jti]


# Configure JWT to check the blocklist
@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(jwt_header, jwt_payload):
  cleanup_expired_tokens()  # Run cleanup on each token check
  jti = jwt_payload["jti"]
  return jti in blocklist


# Define the User and Book models
class User(db.Model):
  
  id = Column(Integer, primary_key=True)
  username = Column(String(80), unique=True, nullable=False)
  password_hash = Column(String(128))

  def set_password(self, password):
      self.password_hash = generate_password_hash(password)

  def check_password(self, password):
      return check_password_hash(self.password_hash, password)


class Book(db.Model):
  
  id = Column(Integer, primary_key=True)
  title = Column(String(80), nullable=False)
  author = Column(String(80), nullable=False)
  isbn = Column(String(20), unique=True, nullable=False)
  genre = Column(String(50), nullable=True)
  description = Column(String, nullable=True)
  publication_date = Column(Date, nullable=True)

  __table_args__ = (
      CheckConstraint(genre.in_(['Fiction', 'Non-fiction', 'Science Fiction', 'Mystery', 'Fantasy'])),
  )


@app.before_first_request
def create_tables():
  db.create_all()


# Routes for user authentication
@app.route('/register', methods=['POST'])
def register():
  """
    Register a new user
    ---
    tags:
      - Authentication
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - username
            - password
          properties:
            username:
              type: string
              description: The username for the new user
            password:
              type: string
              description: The password for the new user
    responses:
      201:
        description: User created successfully
        schema:
          type: object
          properties:
            msg:
              type: string
              example: User created successfully
      409:
        description: Username already exists
  """
  username = request.json.get('username')
  password = request.json.get('password')
  if User.query.filter_by(username=username).first():
      _logger.info(f"Registration failed: Username {username} already exists")
      return jsonify({'msg': 'Username already exists'}), 409
  user = User(username=username)
  user.set_password(password)
  db.session.add(user)
  db.session.commit()
  _logger.info(f"User registered successfully: {username}")
  return jsonify({'msg': 'User created successfully'}), 201
  
  
@app.route('/login', methods=['POST'])
def login():
  """
    Login user
    ---
    tags:
      - Authentication
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - username
            - password
          properties:
            username:
              type: string
              description: The username of the user
            password:
              type: string
              description: The password of the user
    responses:
      200:
        description: Login successful
      401:
        description: Bad username or password
  """
  username = request.json.get('username')
  password = request.json.get('password')
  user = User.query.filter_by(username=username).first()
  if user and user.check_password(password):
      access_token = create_access_token(identity=username)
      refresh_token = create_refresh_token(identity=username)
      _logger.info(f"User logged in successfully: {username}")
      return jsonify(access_token=access_token, refresh_token=refresh_token), 200
  else:
      _logger.warning(f"Login failed: Bad username or password for {username}")
      return jsonify({'msg': 'Bad username or password'}), 401


@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
  """
    Logout user by adding the token to the blocklist
    ---
    tags:
      - Authentication
    security:
      - BearerAuth: []
    responses:
      200:
        description: Logout successful
        content:
        schema:
          type: object
          properties:
            msg:
              type: string
              example: "Logout successful"
      401:
        description: Unauthorized - No or invalid JWT provided
      500:
        description: Server error
  """
  jti = get_jwt()["jti"]
  exp = datetime.fromtimestamp(get_jwt()["exp"], tz=timezone.utc)  # Get token expiration time
  blocklist[jti] = exp  # Add token to blocklist with expiration
  _logger.info(f"User logged out: token {jti} added to blocklist")
  return jsonify({"msg": "Logout successful"}), 200


@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
  current_user = get_jwt_identity()
  new_access_token = create_access_token(identity=current_user)
  _logger.info(f"Access token refreshed for user: {current_user}")
  return jsonify(access_token=new_access_token)


@app.route('/books', methods=['POST'])
@jwt_required()
def create_book():
  """
    Create a new book
    ---
    tags:
      - Books
    security:
      - BearerAuth: []  
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - title
            - author
            - isbn
          properties:
            title:
              type: string
              description: Title of the book
            author:
              type: string
              description: Author of the book
            isbn:
              type: string
              description: ISBN number of the book
            genre:
              type: string
              description: Genre of the book (optional)
            publication_date:
              type: string
              format: date
              description: Publication date in YYYY-MM-DD format (optional)
            description:
              type: string
              description: Description of the book (optional)
    responses:
      201:
        description: Book created successfully
        schema:
          type: object
          properties:
            id:
              type: integer
              example: 1
            title:
              type: string
              example: "Example Title"
            author:
              type: string
              example: "Author Name"
            isbn:
              type: string
              example: "1234567890123"
            genre:
              type: string
              example: "Fiction"
            publication_date:
              type: string
              example: "2023-10-01"
            description:
              type: string
              example: "A thrilling new novel"
      400:
        description: Missing required fields
      500:
        description: Database error
  """
  data = request.get_json()
  required_fields = ['title', 'author', 'isbn']
  if not all(data.get(field) for field in required_fields):
      _logger.warning("Book creation failed: Missing required fields")
      return jsonify({'error': 'Missing required fields'}), 400

  if 'publication_date' in data and data['publication_date']:
      try:
          data['publication_date'] = datetime.strptime(data['publication_date'], '%Y-%m-%d')
      except ValueError:
          _logger.warning("Book creation failed: Invalid date format")
          return jsonify({'error': 'Invalid date format, should be YYYY-MM-DD'}), 400

  new_book = Book(**data)
  db.session.add(new_book)
  try:
      db.session.commit()
      _logger.info(f"Book created successfully: {new_book.title}")
      return jsonify({
          'id': new_book.id,
          'title': new_book.title,
          'author': new_book.author,
          'isbn': new_book.isbn,
          'genre': new_book.genre,
          'publication_date': new_book.publication_date.strftime('%Y-%m-%d') if new_book.publication_date else None,
          'description': new_book.description
      }), 201
  except Exception as e:
      db.session.rollback()
      _logger.error(f"Database error on book creation: {str(e)}")
      return jsonify({'error': 'Database error', 'message': str(e)}), 500


@app.route('/books', methods=['GET'])
@jwt_required()
def list_books():
  """
    List all books
    ---
    tags:
      - Books
    security:
      - BearerAuth: []
    responses:
      200:
        description: A list of all books
        schema:
          type: array
          items:
            type: object
            properties:
              id:
                type: integer
                example: 1
                description: The ID of the book
              title:
                type: string
                example: "Book Title"
                description: The title of the book
              author:
                type: string
                example: "Author Name"
                description: The author of the book
      401:
        description: Unauthorized - No or invalid JWT provided
      500:
        description: Server error
  """
  books = Book.query.all()
  _logger.info("Books retrieved successfully")
  return jsonify([{'id': book.id, 'title': book.title, 'author': book.author} for book in books])


@app.route('/books/<int:book_id>', methods=['GET'])
@jwt_required()
def get_book(book_id):
  """
    Retrieve a book by ID
    ---
    tags:
      - Books
    security:
      - BearerAuth: []
    parameters:
      - name: book_id
        in: path
        required: true
        type: integer
        description: The ID of the book to retrieve
    responses:
      200:
        description: Book retrieved successfully
        schema:
          type: object
          properties:
            id:
              type: integer
              example: 1
            title:
              type: string
              example: "Book Title"
            author:
              type: string
              example: "Author Name"
            isbn:
              type: string
              example: "1234567890123"
            genre:
              type: string
              example: "Fiction"
            publication_date:
              type: string
              example: "2023-10-01"
            description:
              type: string
              example: "Description of the book"
      404:
        description: Book not found
        schema:
          type: object
          properties:
            error:
              type: string
              example: "Book not found"
      401:
        description: Unauthorized - No or invalid JWT provided
  """
  book = Book.query.get(book_id)
  if book:
      _logger.info(f"Book retrieved successfully: {book.title}")
      return jsonify({
          "id": book.id,
          "title": book.title,
          "author": book.author,
          "isbn": book.isbn,
          "genre": book.genre,
          "publication_date": book.publication_date.strftime('%Y-%m-%d') if book.publication_date else None,
          "description": book.description
      }), 200
  else:
      _logger.warning(f"Book not found: ID {book_id}")
      return jsonify({"error": "Book not found"}), 404


@app.route('/books/<int:book_id>', methods=['DELETE'])
@jwt_required()
def delete_book(book_id):
  """
    Delete a book by ID
    ---
    tags:
      - Books
    security:
      - BearerAuth: []
    parameters:
      - name: book_id
        in: path
        required: true
        type: integer
        description: The ID of the book to delete
    responses:
      200:
        description: Book deleted successfully
        schema:
          type: object
          properties:
            message:
              type: string
              example: "Book with ID 1 has been deleted."
      404:
        description: Book not found
        schema:
          type: object
          properties:
            error:
              type: string
              example: "Book not found"
      401:
        description: Unauthorized - No or invalid JWT provided
  """  
  book = Book.query.get(book_id)
  if book:
      db.session.delete(book)
      db.session.commit()
      _logger.info(f"Book deleted successfully: ID {book_id}")
      return jsonify({"message": f"Book with ID {book_id} has been deleted."}), 200
  else:
      _logger.warning(f"Book not found for deletion: ID {book_id}")
      return jsonify({"error": "Book not found"}), 404


@app.route('/books/<int:book_id>', methods=['PUT'])
@jwt_required()
def update_book(book_id):
  """
  Update a book by ID
  ---
  tags:
    - Books
  security:
    - BearerAuth: []
  parameters:
    - name: book_id
      in: path
      required: true
      type: integer
      description: The ID of the book to update
    - name: body
      in: body
      required: true
      schema:
        type: object
        properties:
          title:
            type: string
            description: The new title of the book
            example: "Updated Book Title"
          author:
            type: string
            description: The new author of the book
            example: "Updated Author"
          isbn:
            type: string
            description: The new ISBN of the book
            example: "1234567890123"
          genre:
            type: string
            description: The genre of the book
            example: "Fiction"
          publication_date:
            type: string
            format: date
            description: The publication date of the book in YYYY-MM-DD format
            example: "2023-01-01"
          description:
            type: string
            description: A brief description of the book
            example: "An updated description of the book."
  responses:
    200:
      description: Book updated successfully
      schema:
        type: object
        properties:
          id:
            type: integer
            example: 1
          title:
            type: string
            example: "Updated Book Title"
          author:
            type: string
            example: "Updated Author"
          isbn:
            type: string
            example: "1234567890123"
          genre:
            type: string
            example: "Fiction"
          publication_date:
            type: string
            example: "2023-01-01"
          description:
            type: string
            example: "An updated description of the book."
    404:
      description: Book not found
    400:
      description: Bad request - invalid data format
    500:
      description: Server error
  """  
  data = request.get_json()
  book = Book.query.get(book_id)
  if not book:
      _logger.warning(f"Book not found for update: ID {book_id}")
      return jsonify({"error": "Book not found"}), 404

  for key, value in data.items():
      if hasattr(book, key):
          if key == 'publication_date':
              value = datetime.strptime(data[key], '%Y-%m-%d')
          setattr(book, key, value)
  db.session.commit()
  _logger.info(f"Book updated successfully: {book.title}")
  return jsonify({
      "id": book.id,
      "title": book.title,
      "author": book.author,
      "isbn": book.isbn,
      "genre": book.genre,
      "publication_date": book.publication_date.strftime('%Y-%m-%d') if book.publication_date else None,
      "description": book.description
  }), 200

    
if __name__ == '__main__':
  app.run(host='0.0.0.0', port=5000)

