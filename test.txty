import base64
import json
from PyPDF2 import PdfFileReader, PdfReader
from pdf2image import convert_from_path, convert_from_bytes
import smtplib
import ssl
import random
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import math
import re
import sys
import uuid
import json
from urllib.parse import urljoin
import openai
from asyncio import exceptions
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import deepl
import requests

import torch
import numpy as np
import io
import webcolors
import cv2
import easyocr
from flask import Flask, jsonify, request, Response
from azure.cosmos import CosmosClient
from azure.storage.blob import BlobServiceClient
from PIL import Image
from io import BytesIO
import pyscrypt
import hmac
import hashlib
import secrets
import time
import os
import random
import string
from azure.core.exceptions import AzureError
from werkzeug.utils import secure_filename

app = Flask(__name__)
model = torch.hub.load('ultralytics/yolov5', 'yolov5l', pretrained=True)
# model = torch.load("model.pt")
# Your Cosmos DB connection details
URL = 'https://fye.documents.azure.com:443/'
KEY = '3mRNX6IKinLF9GzU8KgHmuwtCbe8aikiwgj1coLaBQ7VzwVJZsn1Zezwfv7DpiQo0jJR0ZMcbaQSACDbaUwIGQ=='
DATABASE_NAME = 'fyeDb'
CONTAINER_NAME_Volunteer = 'volunteersApp'
CONTAINER_NAME_Users = 'usersApp'
CONTAINER_NAME_Posts = 'postsApp'
CONTAINER_NAME_Characters = 'characters'
CONTAINER_NAME_PostsProduction = "postsProduction"
CONTAINER_NAME_UsersProduction = "usersProduction"
CONTAINER_NAME_VolunteerProduction = "volunteerProduction"
CONTAINER_NAME_SharedContent = "sharedContent"

# openai.api_key = "8e5c758c6f014aab87c628965fee43d7"
openai.api_key = "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"
# openai.api_base = "https://fyenewai.openai.azure.com/"  # your endpoint should look like the following https://YOUR_RESOURCE_NAME.openai.azure.com/
# openai.api_type = 'azure'
# # openai.api_version = '2023-05-15'  # this may change in the future
# deployment_name = 'gptDeploy'  # This will correspond to the custom name you chose for your deployment when you deployed a model.
CONNECTION_STRING = "DefaultEndpointsProtocol=https;AccountName=fyestorage;AccountKey=1iXz09iW2gU8N54HW4k+4vQMsjxkvhKIyJn7/1rtXMl8fVBWdZI+qO1sXtgymA3Xkj8GqEIfzPOa+AStBBYd2g==;EndpointSuffix=core.windows.net"
CONNECTION_STRING_EMAIL = "endpoint=https://mailingservice.germany.communication.azure.com/;accesskey=XUHUAfdk5EwaKBA+CIySkniXmvA3yXaDhTSTkB3VoMLduaSjHQJOq5vMaVKVFTVEQRONZipfGhNitph27R0PrA=="
CONTAINER_NAME_IMAGE = "fye"
BASE_URL = "https://fyestorage.blob.core.windows.net/fye/"
EXTENSIONS = [".jpg", ".png", ".mp4", ".pdf"]
MAX_WORKERS = 20
ALLOWED_MIME_TYPES = {'video/mp4', 'image/jpeg', 'image/png', "application/pdf"}
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'mp4', "pdf"}

# Create a ThreadPoolExecutor instance
executor = ThreadPoolExecutor(max_workers=5)
client = CosmosClient(URL, credential=KEY)
database = client.get_database_client(DATABASE_NAME)
container_users = database.get_container_client(CONTAINER_NAME_Users)
container_volunteer = database.get_container_client(CONTAINER_NAME_Volunteer)
container_posts = database.get_container_client(CONTAINER_NAME_Posts)
container_characters = database.get_container_client(CONTAINER_NAME_Characters)
container_content = database.get_container_client(CONTAINER_NAME_SharedContent)

container_usersProduction = database.get_container_client(CONTAINER_NAME_UsersProduction)
container_volunteerProduction = database.get_container_client(CONTAINER_NAME_VolunteerProduction)
container_postsProduction = database.get_container_client(CONTAINER_NAME_PostsProduction)


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def sort_key(item):
    # Return a very old date for None values to push them to the end
    return item[1]['date'] if item[1]['date'] is not None else "1900-01-01 00:00:00.000000 UTC"


def generate_random_code():
    return random.randint(100000, 999999)


def generate_salt(length=16):
    """Generate a random salt."""
    # The os.urandom function generates random bytes suitable for cryptographic use.
    # The number of bytes is specified by the 'length' parameter.
    salt = os.urandom(length)
    return salt.hex()


def generate_token(email):
    # current time to set the expiration
    timestamp = str(int(time.time()))
    email = email.split("@")[0]
    msg = email + '|' + timestamp
    SECRET_KEY = secrets.token_bytes(64)
    # Create HMAC object
    hmac_obj = hmac.new(SECRET_KEY, msg.encode(),
                        hashlib.sha256)
    hmac_signature = hmac_obj.hexdigest()

    # Creating the token by concatenating username, timestamp, and signature
    token = base64.b64encode(f"{email}|{timestamp}|{hmac_signature}".encode()).decode()
    return token


def get_user_posts_by_token(token):
    query = "SELECT * FROM c WHERE c.activeDevice.token = '{}'".format(token)
    item_user = list(container_users.query_items(query=query, enable_cross_partition_query=True))
    user_all_posts = {'path': [], 'favorite': [], 'date': [], 'aiComment': [], 'volunteerComment': [], "title": [],
                      "language": [], "posts": []}

    if item_user:
        for post in item_user[0]["posts"]:
            user_all_posts['path'].append(post['name'])

        user_all_posts["language"] = item_user[0]["activeDevice"]["language"]

        query_post = "SELECT * FROM c WHERE c.author.name = '{}'".format(item_user[0]["__key__"]["name"])
        post_user = list(container_posts.query_items(query=query_post, enable_cross_partition_query=True))

        # Create a dictionary to store the data for matching paths
        path_data = {}

        for item in post_user:
            key = item["__key__"]["name"]
            if key in user_all_posts['path']:
                path_data[key] = {
                    'date': item['date'],
                    'aiComment': item["images"]["d_0"]['aiComment'],
                    'volunteerComment': item["images"]["d_0"]['volunteerComment'],
                    'title': item["title"],
                    'favorite': item["favorite"]
                }

        # Filter out elements where the key doesn't exist in path_data
        user_all_posts['path'] = [key for key in user_all_posts['path'] if key in path_data]
        user_all_posts['date'] = [path_data[key]['date'] for key in user_all_posts['path']]
        user_all_posts['aiComment'] = [path_data[key]['aiComment'] for key in user_all_posts['path']]
        user_all_posts['volunteerComment'] = [path_data[key]['volunteerComment'] for key in user_all_posts['path']]
        user_all_posts['title'] = [path_data[key]['title'] for key in user_all_posts['path']]
        user_all_posts['favorite'] = [path_data[key]['favorite'] for key in user_all_posts['path']]

    return user_all_posts


def get_user_posts_by_id(user_id):
    # Query the user's data using the provided ID
    query = "SELECT * FROM c WHERE c.__key__.name = '{}'".format(user_id)
    item_post = list(container_posts.query_items(query=query, enable_cross_partition_query=True))

    user_all_posts = {'favorite': [], 'date': [], 'aiComment': [], 'volunteerComment': [], "title": [], "content": [],
                      "images": {}, "volunteerAIReview": "", "userAIReview": ""}

    for post in item_post:
        user_all_posts['date'].append(post['date'])
        user_all_posts['aiComment'].append(post["images"]["d_0"]['aiComment'])
        user_all_posts['volunteerComment'].append(post["images"]["d_0"]['volunteerComment'])
        user_all_posts['title'].append(post["title"])
        user_all_posts['images'] = post["images"]
        user_all_posts["favorite"] = post["favorite"]
        user_all_posts["volunteerAIReview"] = post["volunteerAIReview"]
        user_all_posts["userAIReview"] = post["userAIReview"]

        # If volunteerComment is not null, add it to content. Otherwise, add aiComment
        if post["images"]["d_0"]['volunteerComment']:
            user_all_posts['content'].append(post["images"]["d_0"]['volunteerComment'])
        else:
            user_all_posts['content'].append(post["images"]["d_0"]['aiComment'])

    return user_all_posts


# will add favorite and images

def transform_and_sort_posts(posts_data):
    transformed_data = {
        key: {
            'favorite': posts_data['favorite'][i] if i < len(posts_data['date']) else None,
            'date': posts_data['date'][i] if i < len(posts_data['date']) else None,
            'volunteerComment': posts_data['volunteerComment'][i] if i < len(posts_data['volunteerComment']) else None,
            'title': posts_data['title'][i] if i < len(posts_data['title']) else None,
            "aiComment": posts_data['aiComment'][i] if i < len(posts_data['aiComment']) else None,
        }
        for i, key in enumerate(posts_data['path'])
    }

    # Sort the transformed_data dictionary by the 'date' field
    sorted_data = dict(sorted(transformed_data.items(), key=sort_key, reverse=True))

    return sorted_data


def create_uid(user_id=None):
    user_id = str(uuid.uuid4()) if user_id is None else user_id
    return user_id


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    password = data.get("password")
    email = data.get("email")

    if not email or not password:
        return jsonify(error="Invalid input"), 400

    # user_data = container_users.find_one({"username": username})
    user_query = f"SELECT * FROM c WHERE c.email = '{email}'"
    user_data = list(container_users.query_items(query=user_query, enable_cross_partition_query=True))

    if not user_data:
        return jsonify(error="User not found"), 404

    stored_hash = user_data[0]["passwordHash"]
    password_bytes = password.encode('utf-8')

    if stored_hash == "":
        salt = generate_salt(16)
        salt_bytes = salt.encode('utf-8')
        computed_hash = pyscrypt.hash(password=password_bytes,
                                      salt=salt_bytes,
                                      N=1024, r=8, p=1, dkLen=256)
        computed_hash_hex = computed_hash.hex()
        token = generate_token(email)
        user_data[0]["activeDevice"]["token"] = token
        user_data[0]["passwordHash"] = computed_hash_hex
        user_data[0]["salt"] = salt
        container_users.upsert_item(user_data[0]),
        return jsonify(message="Login successful", token=token)

    salt = user_data[0]["salt"]
    salt_bytes = salt.encode("utf-8")
    computed_hash = pyscrypt.hash(password=password_bytes,
                                  salt=salt_bytes,
                                  N=1024, r=8, p=1, dkLen=256)
    computed_hash_hex = computed_hash.hex()
    if computed_hash_hex == stored_hash:
        token = user_data[0]["activeDevice"]["token"]
        container_users.upsert_item(user_data[0])
        return jsonify(token=token), 200
    else:
        return jsonify(error="Invalid credentials"), 401


@app.route("/socialLogin", methods=['POST'])
def socialLogin():
    data = request.get_json()
    uid = data.get("uid")
    # Query to find users with a non-null uuid field
    query = f"SELECT * FROM c WHERE c.uid = '{uid}'"

    user_data = list(container_users.query_items(query=query, enable_cross_partition_query=True))
    if len(user_data) != 0:
        user_document = user_data[0]
        token = user_data[0]["activeDevice"]["token"]
        container_users.upsert_item(body=user_document)
        response = {
            'success': True,  # or some other meaningful message
            'token': token
        }
        return jsonify(response), 200

    volunteer_data = list(container_volunteer.query_items(query=query, enable_cross_partition_query=True))

    if len(volunteer_data) != 0:
        volunteer_document = user_data[0]
        token = user_data[0]["activeDevice"]["token"]
        container_volunteer.upsert_item(body=volunteer_document)
        response = {
            'success': True,  # or some other meaningful message
            'token': token
        }
        return jsonify(response), 200

    return jsonify(False), 200


@app.route('/add_post', methods=['POST'])
def add_post():
    email = request.json.get('email')
    title = request.json.get('title')
    content = request.json.get('content')
    weblink = request.json.get('weblink')
    token = request.json.get('token')

    post_id = str(uuid.uuid4())
    # Get current date and time
    current_date = datetime.utcnow().isoformat()
    # Create a new item in Cosmos DB
    item = {
        'id': post_id,  # Assuming title is unique, otherwise use a different unique id
        'email': email,
        'title': title,
        'content': content,
        'weblink': weblink,
        "token": token,
        "confirmation": False,
        'date': current_date
    }

    container_content.upsert_item(item)

    return jsonify({'message': 'Item added successfully!'}), 200


@app.route('/get_confirmed_posts', methods=['GET'])
def get_confirmed_posts():
    # Query items with confirmation set to true
    query = "SELECT p.title, p.content, p.weblink, p.date FROM p WHERE p.confirmation = true"
    items = list(container_content.query_items(query=query, enable_cross_partition_query=True))

    return jsonify(items), 200


@app.route("/register", methods=['POST'])
def register():
    try:
        data = request.get_json()
        email = data.get("email")
        name = data.get("name")
        phone = data.get("telNo")
        language = data.get("language")
        password = data.get("password")
        descriptor = data.get("descriptor")
        uid = data.get("uid")
        languages = data.get("languages")

        if descriptor is not None:
            email_query = f'SELECT * FROM c WHERE c.email = "{email}"'
            existing_volunteer = list(container_volunteer.query_items(
                query=email_query,
                enable_cross_partition_query=True  # Enable querying over all logical partitions
            ))

            if existing_volunteer:
                return jsonify({"error": "A volunteer with this email already exists."}), 400
        else:
            # Check if user already exists
            email_query = f'SELECT * FROM c WHERE c.email = "{email}"'
            existing_users = list(container_users.query_items(
                query=email_query,
                enable_cross_partition_query=True  # Enable querying over all logical partitions
            ))

            if existing_users:
                return jsonify({"error": "A user with this email already exists."}), 400

        # If user does not exist, proceed with registration
        password_bytes = password.encode('utf-8')
        salt = generate_salt(16)
        salt_bytes = salt.encode('utf-8')
        computed_hash = pyscrypt.hash(password=password_bytes, salt=salt_bytes, N=1024, r=8, p=1, dkLen=256)
        computed_hash_hex = computed_hash.hex()
        token = generate_token(email)
        if not uid:
            id = create_uid()
        else:
            id = uid

        user_document = {
            "id": id,
            "email": email,
            "name": name,
            "telNo": phone,
            "overallScore": "0",
            "postScoreTotal": "0",
            "descriptedScoreTotal": "0",
            "version": "1.0.1",
            "salt": salt,
            "passwordHash": computed_hash_hex,
            "uid": id,
            "activeDevice": {
                "language": language,
                "token": token
            },
            "status": "false",  # Consider using boolean False
            "languages": [],
            "posts": [],
            "kvkk": True,
            "kam": True,
            "descriptor": descriptor,
            "monthlyDescriptorScore": 0,
            "allTimeDescriptorScore": 0,
            "badges": []
        }

        if descriptor == "True" or descriptor == "true":
            user_document["__key__"] = {"path": f'"volunteer", "{id}"',
                                        "kind": "volunteer",
                                        "name": id}
            user_document["languages"] = languages
            container_volunteer.upsert_item(body=user_document)
            return jsonify({"message": "Volunteer registered successfully!", "token": token}), 201
        else:
            user_document["__key__"] = {"path": f'"users", "{id}"',
                                        "kind": "users",
                                        "name": id}
            container_users.upsert_item(body=user_document)
            return jsonify({"message": "User registered successfully!", "token": token}), 201

    except exceptions.CosmosHttpResponseError as e:
        # Handle specific database exceptions
        return jsonify({"error": str(e)}), 400

    except Exception as e:
        # General exception handling
        return jsonify({"error": str(e)}), 400


# display last 10 posts for app
@app.route('/displayPosts', methods=['GET'])
def get_tenPosts():
    token = request.headers.get("Authorization")[7:]
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    user_all_posts = get_user_posts_by_token(token)
    transformed_data = transform_and_sort_posts(user_all_posts)
    # if date is null ise almasak mi?

    # Fetch the last 10 image paths from user_all_posts['path']
    last_10_image_paths = list(transformed_data.keys())
    for path in last_10_image_paths:
        image_path_without_extension = "storage/images/" + path
        transformed_data[path]['image_data'] = fetch_images_as_path(image_path_without_extension)

    desired_format = []
    for key, value in transformed_data.items():
        if value.get('image_data'):
            img_data = {
                "0": value['image_data'][0] if value.get('image_data') else None
            }
            entry = {
                "date": value['date'],
                "favorite": value['favorite'],
                "Id": key,
                "image_data": img_data
            }
            desired_format.append(entry)

    start = (page - 1) * per_page
    end = start + per_page

    return jsonify({
        'data': desired_format[start:end],
        'current_page': page,
        'per_page': per_page,
        'total_items': len(desired_format),
        "total_pages": math.ceil(len(desired_format) / per_page)
    })


@app.route('/deletePost', methods=['DELETE'])
def delete_post():
    try:
        # Retrieve post_id from request
        post_id = request.json.get("post_id")

        if not post_id:
            return jsonify({"error": "Post ID is required"}), 400

        # Query to find the post using post_id
        posts_query = f"SELECT * FROM c WHERE c.__key__.name = '{post_id}'"
        posts_items = list(container_posts.query_items(query=posts_query, enable_cross_partition_query=True))

        # Check if post is found
        if not posts_items:
            return jsonify({"error": "Post not found"}), 404

        # Delete the post
        container_posts.delete_item(item=posts_items[0], partition_key=posts_items[0]['id'])

        return jsonify({"success": f"Post {post_id} has been deleted"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/deleteUser', methods=['DELETE'])
def delete_user():
    try:
        # Retrieve token from request
        token = request.headers.get("Authorization")[7:]

        # Query to find the user using token
        user_query = f"SELECT * FROM c WHERE c.activeDevice.token = '{token}'"
        user_items = list(container_users.query_items(query=user_query, enable_cross_partition_query=True))

        # Check if user is found
        if not user_items:
            return jsonify({"error": "User not found"}), 404

        # Extract post ids from user_items
        post_ids = [post['name'] for post in user_items[0]["posts"]]

        # Delete the user
        container_users.delete_item(item=user_items[0], partition_key=user_items[0]['id'])

        # Iterate through each post id and delete related posts
        for post_id in post_ids:
            # Query to find posts linked with the post's ID and delete them
            posts_query = f"SELECT * FROM c WHERE c.__key__.name = '{post_id}'"
            posts_items = list(
                container_posts.query_items(query=posts_query, enable_cross_partition_query=True))

            for post in posts_items:
                container_posts.delete_item(item=posts_items[0], partition_key=posts_items[0]['id'])

        return jsonify({"success": f"User and related posts have been deleted"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/allPosts', methods=['GET'])
def get_allPosts():
    token = request.headers.get("Authorization")[7:]
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    user_all_posts = get_user_posts_by_token(token)
    transformed_data = transform_and_sort_posts(user_all_posts)

    # Fetch all available image paths for each post
    for path in transformed_data.keys():
        image_path_without_extension = "storage/images/" + path
        transformed_data[path]['image_data'] = fetch_images_as_path(image_path_without_extension)

    desired_format = []
    for key, value in transformed_data.items():
        if value.get('image_data'):
            img_data = {}
            for idx, img_path in enumerate(value.get('image_data', [])):
                img_data[str(idx)] = img_path

            entry = {
                "date": value['date'],
                "favorite": value['favorite'],
                "Id": key,
                "image_data": img_data
            }
            desired_format.append(entry)

    start = (page - 1) * per_page
    end = start + per_page

    return jsonify({
        'data': desired_format[start:end],
        'current_page': page,
        'per_page': per_page,
        'total_items': len(desired_format),
        "total_pages": math.ceil(len(desired_format) / per_page)
    })


@app.route('/favoritePosts', methods=['GET'])
def get_favoritePosts():
    token = request.headers.get("Authorization")[7:]
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    user_all_posts = get_user_posts_by_token(token)
    transformed_data = transform_and_sort_posts(user_all_posts)

    favorites_posts = {k: v for k, v in transformed_data.items() if v['favorite']}

    # Fetch all available image paths for each favorite post
    for path, data in favorites_posts.items():
        image_path_without_extension = "storage/images/" + path
        data['image_data'] = fetch_images_as_path(image_path_without_extension)

    desired_format = []
    for key, value in favorites_posts.items():
        img_data = {}
        for idx, img_path in enumerate(value.get('image_data', [])):
            img_data[str(idx)] = img_path

        entry = {
            "date": value['date'],
            "favorite": value['favorite'],
            "Id": key,
            "image_data": img_data
        }
        desired_format.append(entry)

    start = (page - 1) * per_page
    end = start + per_page

    return jsonify({
        'data': desired_format[start:end],
        'current_page': page,
        'per_page': per_page,
        'total_items': len(desired_format),
        "total_pages": math.ceil(len(desired_format) / per_page)
    })


@app.route("/updateFavorite", methods=['POST'])
def update_favoritePosts():
    decoded_data = request.data.decode('utf-8')
    parsed_data = json.loads(decoded_data)
    received_id = parsed_data.get('id')
    received_favorite = parsed_data.get("favorite")

    # Query the Cosmos DB to retrieve the document
    query = "SELECT * FROM c WHERE c.__key__.name = '{}'".format(received_id)
    items = list(container_posts.query_items(query=query, enable_cross_partition_query=True))

    if items:
        item = items[0]
        item["favorite"] = received_favorite
        container_posts.replace_item(item, item)
        response_message = "Updated successfully"
    else:
        response_message = f"No document found with id: {received_id}"

    return jsonify(response_message)


# @app.route('/forgetPasswordEmail', methods=['POST'])
# def email_endpoint():
#     data = request.get_json()
#     subject = "FYE Forgot My Password"
#     to_email = data.get("to_email")
#     from_email = 'info@fromyoureyes.com'
#     # Check if required data is available
#     if not data or 'to_email' not in data or 'content' not in data:
#         return jsonify({'error': 'Bad Request', 'message': 'Missing parameters'}), 400
#
#     message = {
#         "content": {
#             "subject": subject,
#             "plainText": "This is the body",
#         },
#         "recipients": {
#             "to": [
#                 {
#                     "address": to_email,
#                     "displayName": "Customer Name"
#                 }
#             ]
#         },
#         "senderAddress": from_email
#     }
#     # Send the email using the function
#     # response = send_email(
#     #     from_email=data['from_email'],
#     #     to_email='info@fromyoureyes.com',  # replace with your company's email
#     #     subject=data['subject'],
#     #     content=data['content']
#     # )
#
#     if response and response.status_code == 202:
#         return jsonify({'success': True, 'message': 'Email sent successfully'}), 200
#     else:
#         return jsonify({'success': False, 'message': 'Email failed to send'}), 500
#
#
# # More configurations and potentially more routes...
def send_email_via_smtp(user_email, code):
    receiver_email = user_email
    subject = "Your password reset code"
    smtp_server = "smtp-relay.brevo.com"
    smtp_port = 587  # Port for starttls
    smtp_username = "fye.forgotmypassword@fromyoureyes.app"
    smtp_password = "yaIN3T81AJRO0MSE"

    body = f"Your password reset code is {code}"
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = smtp_username
    msg['To'] = receiver_email

    # Create a secure SSL context
    context = ssl.create_default_context()

    try:
        # Establishing a connection with the server
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.ehlo()  # Can be omitted

        # Start TLS
        server.starttls(context=context)  # Upgrade the connection to encrypted
        server.ehlo()  # Can be omitted

        # Login to the email server
        server.login(smtp_username, smtp_password)

        # Sending the email
        server.sendmail(msg['From'], receiver_email, msg.as_string())

    except smtplib.SMTPException as e:
        print(f"An error occurred: {e}")

    finally:
        # Closing the connection
        server.quit()


def send_email_via_smtp_contact(recipient_email, content):
    receiver_email = recipient_email
    subject = "Contact Us"
    smtp_server = "smtp-relay.brevo.com"
    smtp_port = 587  # Port for starttls
    smtp_username = "info@fromyoureyes.app"
    smtp_password = "42VUDmfy7TrI5dck"

    body = f"sender:{recipient_email}, content: {content}"
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = smtp_username
    msg['To'] = smtp_username

    # Create a secure SSL context
    context = ssl.create_default_context()

    try:
        # Establishing a connection with the server
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.ehlo()  # Can be omitted

        # Start TLS
        server.starttls(context=context)  # Upgrade the connection to encrypted
        server.ehlo()  # Can be omitted

        # Login to the email server
        server.login(smtp_username, smtp_password)

        # Sending the email
        server.sendmail(msg['From'], receiver_email, msg.as_string())

    except smtplib.SMTPException as e:
        print(f"An error occurred: {e}")

    finally:
        # Closing the connection
        server.quit()


def send_reset_code(user_email):
    # Generate the temporary password or reset code
    code = generate_random_code()

    try:
        # Query to find the user based on the email address
        users_query = f"SELECT * FROM c WHERE c.email = '{user_email}'"
        user_items = list(container_users.query_items(query=users_query, enable_cross_partition_query=True))

        if user_items:
            # Assuming only one entry for the email
            user = user_items[0]

            # Update the tempPass field
            user['tempPass'] = code

            # Replace the item in the container
            container_users.replace_item(item=user, body=user)

            # Here, send the reset code to the user's email using your preferred email sending method
            send_email_via_smtp(user_email, code)
        else:
            print(f"No user found with email: {user_email}")

    except exceptions.CosmosHttpResponseError as e:
        print(f"An error occurred: {e}")  # For production, consider logging this error.


@app.route('/forgetPasswordEmail', methods=['POST'])
def email_endpoint():
    data = request.get_json()
    recipient_email = data.get("email")
    send_reset_code(recipient_email)
    return jsonify("Success")


def send_email_via_smtp_contact_harmful(recipient_email, content):
    receiver_email = recipient_email
    subject = "Harmful Content"
    smtp_server = "smtp-relay.brevo.com"
    smtp_port = 587  # Port for starttls
    smtp_username = "info@fromyoureyes.app"
    smtp_password = "42VUDmfy7TrI5dck"

    body = f"sender:{recipient_email}, content: {content}"
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = smtp_username
    msg['To'] = smtp_username

    # Create a secure SSL context
    context = ssl.create_default_context()

    try:
        # Establishing a connection with the server
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.ehlo()  # Can be omitted

        # Start TLS
        server.starttls(context=context)  # Upgrade the connection to encrypted
        server.ehlo()  # Can be omitted

        # Login to the email server
        server.login(smtp_username, smtp_password)

        # Sending the email
        server.sendmail(msg['From'], receiver_email, msg.as_string())

    except smtplib.SMTPException as e:
        print(f"An error occurred: {e}")

    finally:
        # Closing the connection
        server.quit()


@app.route('/contactUs', methods=['POST'])
def email_us():
    data = request.get_json()
    content = data.get("content")
    recipient_email = data.get("email")
    harmful = data.get("harmful")
    if harmful == "True" or harmful == "true":
        send_email_via_smtp_contact_harmful(recipient_email, content)
    send_email_via_smtp_contact(recipient_email, content)
    return jsonify("Success")


@app.route('/verifyResetCode', methods=['POST'])
def verify_reset_code():
    # Extract the data from the POST request
    data = request.get_json()
    user_email = data.get("email")  # The user's email address
    submitted_code = data.get("code")  # The reset code submitted by the user

    try:
        # Query to find the user based on the email address
        users_query = f"SELECT * FROM c WHERE c.email = '{user_email}'"
        user_items = list(container_users.query_items(query=users_query, enable_cross_partition_query=True))

        if user_items:
            # Assuming only one entry for the email
            user = user_items[0]

            # Check if the submitted code matches the one in the database
            if user['tempPass'] == submitted_code:
                # If the codes match, then the verification is successful
                response = {"status": "success", "message": "Verification successful."}
            else:
                # If the codes don't match, then the verification failed
                response = {"status": "failed", "message": "Invalid code. Please try again."}
        else:
            response = {"status": "failed", "message": f"No user found with email: {user_email}"}

    except exceptions.CosmosHttpResponseError as e:
        print(f"An error occurred: {e}")  # For production, consider logging this error.
        response = {"status": "error", "message": "An error occurred while verifying the code."}

    return jsonify(response)


@app.route('/changePassword', methods=['POST'])
def change_password():
    data = request.get_json()
    user_email = data.get("email")  # The user's email address
    new_password = data.get("new_password")  # The new password from the user

    # Create the salt and hash the password
    password_bytes = new_password.encode('utf-8')
    salt = generate_salt(16)  # Generate a random salt; you can change the length as needed
    salt_bytes = salt.encode('utf-8')
    computed_hash = pyscrypt.hash(password=password_bytes, salt=salt_bytes, N=1024, r=8, p=1, dkLen=256)
    computed_hash_hex = computed_hash.hex()  # The hashed password

    try:
        # Query to find the user based on the email address
        users_query = f"SELECT * FROM c WHERE c.email = '{user_email}'"
        user_items = list(container_users.query_items(query=users_query, enable_cross_partition_query=True))

        if user_items:
            # Assuming only one entry for the email
            user = user_items[0]

            # Update the password field in the user record
            user['password'] = computed_hash_hex
            user['salt'] = salt  # Store the salt with the user's record for future password verification

            # Replace the item in the container with the updated information
            container_users.replace_item(item=user, body=user)

            response = {"status": "success", "message": "Password updated successfully."}
        else:
            response = {"status": "failed", "message": f"No user found with email: {user_email}"}

    except exceptions.CosmosHttpResponseError as e:
        print(f"An error occurred: {e}")  # For production, consider logging this error.
        response = {"status": "error", "message": "An error occurred while updating the password."}

    return jsonify(response)


@app.route("/updateTitle", methods=['POST'])
def update_titlePosts():
    decoded_data = request.data.decode('utf-8')
    parsed_data = json.loads(decoded_data)
    received_id = parsed_data.get('id')
    received_favorite = parsed_data.get("title")

    # Query the Cosmos DB to retrieve the document
    query = "SELECT * FROM c WHERE c.__key__.name = '{}'".format(received_id)
    items = list(container_posts.query_items(query=query, enable_cross_partition_query=True))

    if items:
        item = items[0]
        item["title"] = received_favorite
        container_posts.replace_item(item, item)
        response_message = "Updated successfully"
    else:
        response_message = f"No document found with id: {received_id}"

    return jsonify(response_message)


@app.route("/changeEmail", methods=['POST'])
def change_Email():
    token = request.headers.get("Authorization")[7:]
    decoded_data = request.data.decode('utf-8')
    parsed_data = json.loads(decoded_data)
    received_Email = parsed_data.get("email")

    # Query the Cosmos DB to retrieve the document
    query = "SELECT * FROM c WHERE c.activeDevice.token = '{}'".format(token)
    items = list(container_users.query_items(query=query, enable_cross_partition_query=True))
    if items:
        item = items[0]
        item["email"] = received_Email
        container_posts.replace_item(item, item)
        response_message = "Updated successfully"
    else:
        response_message = f"No document found with id: {received_Email}"

    return jsonify(response_message)


@app.route("/changePhone", methods=['POST'])
def change_Phone():
    token = request.headers.get("Authorization")[7:]
    decoded_data = request.data.decode('utf-8')
    parsed_data = json.loads(decoded_data)
    received_telNo = parsed_data.get("telNo")

    # Query the Cosmos DB to retrieve the document
    query = "SELECT * FROM c WHERE c.activeDevice.token = '{}'".format(token)
    items = list(container_users.query_items(query=query, enable_cross_partition_query=True))
    if items:
        item = items[0]
        item["telNo"] = received_telNo
        container_posts.replace_item(item, item)
        response_message = "Updated successfully"
    else:
        response_message = f"No document found with id: {received_telNo}"

    return jsonify(response_message)


@app.route("/changeName", methods=['POST'])
def change_Name():
    token = request.headers.get("Authorization")[7:]
    decoded_data = request.data.decode('utf-8')
    parsed_data = json.loads(decoded_data)
    received_name = parsed_data.get("name")

    # Query the Cosmos DB to retrieve the document
    query = "SELECT * FROM c WHERE c.activeDevice.token = '{}'".format(token)
    items = list(container_users.query_items(query=query, enable_cross_partition_query=True))
    if items:
        item = items[0]
        item["name"] = received_name
        container_posts.replace_item(item, item)
        response_message = "Updated successfully"
    else:
        response_message = f"No document found with id: {received_name}"

    return jsonify(response_message)


@app.route("/changePassword", methods=['POST'])
def change_Password():
    token = request.headers.get("Authorization")[7:]
    decoded_data = request.data.decode('utf-8')
    parsed_data = json.loads(decoded_data)
    received_oldPassword = parsed_data.get("oldPassword")
    received_NewPassword = parsed_data.get("newPassword")

    # Query the Cosmos DB to retrieve the document
    query = "SELECT * FROM c WHERE c.activeDevice.token = '{}'".format(token)
    items = list(container_users.query_items(query=query, enable_cross_partition_query=True))
    salt = items[0]["salt"]
    salt_bytes = salt.encode("utf-8")
    passwordHash = items[0]["passwordHash"]
    password_bytes = received_oldPassword.encode('utf-8')
    computed_hash = pyscrypt.hash(password=password_bytes, salt=salt_bytes, N=1024, r=8, p=1, dkLen=256)
    computed_hash_hex = computed_hash.hex()
    if passwordHash == computed_hash_hex:
        item = items[0]
        password_bytes_new = received_NewPassword.encode("utf-8")
        computed_hash_new = pyscrypt.hash(password=password_bytes_new, salt=salt_bytes, N=1024, r=8, p=1, dkLen=256)

        # Convert the new hash to a hexadecimal string format
        computed_hash_new_hex = computed_hash_new.hex()

        item["passwordHash"] = computed_hash_new_hex  # storing the hex string instead of bytes
        container_users.replace_item(item["id"],
                                     item)  # It's recommended to use 'item["id"]' to specify the document to replace
        response_message = "Password updated successfully"
    else:
        response_message = "Incorrect current password provided."

    return jsonify(response_message)


@app.route("/updateScore", methods=['POST'])
def update_score():
    token = request.headers.get("Authorization")[7:]
    decoded_data = request.data.decode('utf-8')
    parsed_data = json.loads(decoded_data)
    received_point = parsed_data.get("point")

    # Try to find the token in users container first
    query_users = "SELECT * FROM c WHERE c.activeDevice.token = '{}'".format(token)
    items_users = list(container_users.query_items(query=query_users, enable_cross_partition_query=True))

    # If found in users container, update the score
    if items_users:
        item = items_users[0]
        item["overallScore"] = int(item.get("overallScore", 0)) + int(received_point)
        item["overallScore"] = str(item["overallScore"])
        container_users.replace_item(item["id"], item)
        response_message = "Updated successfully in users"
        return jsonify(response_message)

    # If not found in users, try to find in volunteers container
    query_volunteers = "SELECT * FROM c WHERE c.activeDevice.token = '{}'".format(token)
    items_volunteers = list(container_volunteer.query_items(query=query_volunteers, enable_cross_partition_query=True))

    # If found in volunteers container, update the score
    if items_volunteers:
        item = items_volunteers[0]
        item["overallScore"] = int(item.get("overallScore", 0)) + int(received_point)
        item["overallScore"] = str(item["overallScore"])
        container_volunteer.replace_item(item["id"], item)
        response_message = "Updated successfully in volunteers"
        return jsonify(response_message)

    # If not found in both containers
    response_message = f"No document found with token: {token}"
    return jsonify(response_message)


@app.route('/descriptorPosts', methods=['GET'])
def get_descriptorPosts():
    token = request.headers.get("Authorization")[7:]
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    user_all_posts = get_user_posts_by_token(token)
    transformed_data = transform_and_sort_posts(user_all_posts)
    descriptor_data = {key: value for key, value in transformed_data.items() if value.get('volunteerComment')}

    for path, data in descriptor_data.items():
        image_path_without_extension = "storage/images/" + path
        data['image_data'] = fetch_images_as_path(image_path_without_extension)

    for key in descriptor_data:
        if "aiComment" in descriptor_data[key]:
            del descriptor_data[key]["aiComment"]

    desired_format = []
    for key, value in descriptor_data.items():
        if not value.get('image_data'):
            img_data = None
        else:
            img_data = {
                "0": value['image_data'][0] if value.get('image_data') else None
            }
        entry = {
            "date": value['date'],
            "Id": key,
            "image_data": img_data,
            "favorite": value["favorite"]
        }
        desired_format.append(entry)

    start = (page - 1) * per_page
    end = start + per_page

    return jsonify({
        'data': desired_format[start:end],
        'current_page': page,
        'per_page': per_page,
        'total_items': len(desired_format),
        "total_pages": math.ceil(len(desired_format) / per_page)
    })


@app.route("/filteredPost", methods=["POST"])
def filteredPosts():
    token = request.headers.get("Authorization")[7:]
    user_all_posts = get_user_posts_by_token(token)
    decoded_data = request.data.decode('utf-8')
    parsed_data = json.loads(decoded_data)
    received_id = parsed_data.get("id")

    user_posts = get_user_posts_by_id(received_id)
    # Check if the post with received_id belongs to the user with the token
    if received_id not in user_all_posts['path']:
        return jsonify(error="Post with given ID does not exist or doesn't belong to the user"), 404

    # Transformed data structure
    transformed_data = {
        'date': user_posts['date'][0] if user_posts['date'] else None,
        'favorite': user_posts["favorite"],
        'Id': received_id,
        'content': [],
        'title': user_posts["title"][0],
        "userAIReview": user_posts["userAIReview"],
        "volunteerAIReview": user_posts["volunteerAIReview"]
    }
    image_path_without_extension = "storage/images/" + transformed_data["Id"]
    list_of_images = {"images": fetch_images_as_path(image_path_without_extension)}

    output = []

    # Function to extract the numeric part from the key
    def key_sort_order(key_string):
        match = re.match(r'd_(\d+)', key_string)
        return int(match.group(1)) if match else float('inf')

    # Extract keys from 'images', sort them by the numeric part
    sorted_keys = sorted(user_posts['images'].keys(), key=key_sort_order)

    # Extract language from user_all_posts
    language = user_all_posts.get('language', None)

    for key in sorted_keys:
        value = user_posts['images'][key]
        comment_data = {}
        # Check if value is structured as expected
        print(f"Value for {key}:", value)
        if value:
            if value.get('volunteerComment') != "" and None:
                comment_data['text'] = value['volunteerComment']
                comment_data['volunteer'] = True
                comment_data["sendtoDescriptor"] = False
                comment_data["media"] = value['media']
            elif value.get('aiComment') is not None:
                if value.get('aiComment'):
                    comment_data['text'] = value['aiComment']
                    comment_data['volunteer'] = False
                    comment_data["sendtoDescriptor"] = False
                    comment_data["media"] = value['media']
                else:
                    comment_data['text'] = "don't have aiComment in desired language"
                    comment_data['volunteer'] = False
                    comment_data["sendtoDescriptor"] = False
                    comment_data["media"] = value['media']
            output.append(comment_data)

    list_of_images = list_of_images["images"]
    min_length = min(len(list_of_images), len(output))

    content = [
        {
            "image": list_of_images[i],
            "text": output[i].get('text', ''),  # use get method with a default value
            "volunteer": output[i].get('volunteer', False),
            "sendtoDescriptor:": output[i].get('sendtoDescriptor', False),
            "media": output[i].get("media", False)  # default to False if not found
        }
        for i in range(min_length)
    ]

    # Add a new field 'hasReview' to each content item
    # Extracting 'volunteerAIReview' and 'userAIReview' from 'user_posts'
    volunteerAIReview = user_posts.get("volunteerAIReview")
    userAIReview = user_posts.get("userAIReview")
    # Check if either 'volunteerAIReview' or 'userAIReview' is not null
    hasReview = volunteerAIReview is not None or userAIReview is not None
    transformed_data["content"] = content
    transformed_data["hasReview"] = hasReview

    # ... [Code for processing images and content] ...

    # No need to add 'hasReview', 'userAIReview', or 'volunteerAIReview' to individual content items

    # ... [Rest of your code for creating response] ..

    # Now, your 'transformed_data' dictionary is ready with the modifications you wanted.
    # 'indent=4' is for pretty-printing
    transformed_data["date"] = transformed_data["date"][0]
    return jsonify(transformed_data)


@app.route('/titledPosts', methods=['GET'])
def get_titledPosts():
    token = request.headers.get("Authorization")[7:]
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    user_all_posts = get_user_posts_by_token(token)
    transformed_data = transform_and_sort_posts(user_all_posts)

    title_posts = {k: v for k, v in transformed_data.items() if v['title']}
    for path, data in title_posts.items():
        image_path_without_extension = "storage/images/" + path
        data['image_data'] = fetch_images_as_path(image_path_without_extension)

    desired_format = []
    for key, value in title_posts.items():
        if not value.get('image_data'):
            img_data = None
        else:
            img_data = {
                "0": value['image_data'][0]
            }
        entry = {
            "date": value['date'],
            "favorite": value['favorite'],
            "Id": key,
            "image_data": img_data,
            "title": value["title"]
        }
        desired_format.append(entry)

    start = (page - 1) * per_page
    end = start + per_page

    return jsonify({
        'data': desired_format[start:end],
        'current_page': page,
        'per_page': per_page,
        'total_items': len(desired_format),
        "total_pages": math.ceil(len(desired_format) / per_page)
    })


def fetch_single_image(blob_service_client, image_path):
    blob_client = blob_service_client.get_blob_client(container=CONTAINER_NAME_IMAGE, blob=image_path)
    try:
        blob_data = blob_client.download_blob()

        # Use PIL to open and resize the image
        image = Image.open(BytesIO(blob_data.readall()))

        # Resize the image
        max_width = 200
        aspect_ratio = image.width / image.height
        new_height = int(max_width / aspect_ratio)
        image_resized = image.resize((max_width, new_height))

        # Convert the resized image back to bytes
        buffer = BytesIO()
        image_format = "JPEG" if ".jpg" in image_path else "PNG"
        image_resized.save(buffer, format=image_format)

        return base64.b64encode(buffer.getvalue()).decode('utf-8')
    except Exception as e:
        return None


@app.route('/details', methods=['GET'])
def get_details():
    token = request.headers.get("Authorization")[7:]
    query = "SELECT * FROM c WHERE c.activeDevice.token = '{}'".format(token)

    user_detail = {}
    items = list(container_users.query_items(query=query, enable_cross_partition_query=True))
    descriptor = False
    container = container_users  # Default to users container

    if not items:
        items = list(container_volunteer.query_items(query=query, enable_cross_partition_query=True))
        descriptor = True
        container = container_volunteer  # Update to volunteers container

    if not items:
        return jsonify({"error": "User not found"}), 404

    user_detail['id'] = items[0]["id"]
    user_detail['name'] = items[0]["name"]
    user_detail['email'] = items[0]["email"]
    user_detail["telNo"] = items[0]["telNo"]
    user_detail['version'] = items[0]["version"]
    user_detail['overallScore'] = items[0]["overallScore"]
    user_detail['descriptor'] = descriptor
    user_detail["badges"] = items[0]["badges"]

    if descriptor:
        user_detail['languages'] = items[0]["languages"]

    # Get all scores from the appropriate container
    query_all_scores = "SELECT c.overallScore FROM c"
    all_scores = [item['overallScore'] for item in
                  container.query_items(query=query_all_scores, enable_cross_partition_query=True)]

    user_score = user_detail.get('overallScore', 0) or 0  # Default to 0 if it's None or not found
    rank = sum(1 for score in all_scores if score and score > user_score) + 1  # 1-based rank
    user_detail['rank'] = rank
    badgesScore = items[0]["allTimeDescriptorScore"]
    # Define the badge thresholds and names
    badges_data = [
        (9, "Acemi, Çaylak"),
        (49, "Azimli, Kararlı"),
        (99, "Meydan Okuyucu"),
        (199, "Usta"),
        (299, "Efsanevi")
    ]
    # Assign badges based on the score
    for threshold, badge_name in badges_data:
        if badgesScore >= threshold:
            user_detail["badges"].append(badge_name)

    print(user_detail["badges"])

    return jsonify(user_detail)


@app.route('/leaderboard_users', methods=['GET'])
def get_leaderboard_users():
    # Query to fetch top 10 users by point from container_users
    query_users = "SELECT TOP 10 c.name, c.overallScore FROM c ORDER BY c.overallScore DESC"
    top_users = list(container_users.query_items(query=query_users, enable_cross_partition_query=True))

    # # Query to fetch top 10 volunteers by point from container_volunteers
    # query_volunteers = "SELECT c.firstName, c.point FROM c ORDER BY c.point DESC TOP 10"
    # top_volunteers = list(container_volunteer.query_items(query=query_volunteers, enable_cross_partition_query=True))

    # Combine and sort both lists by point, then get the top 10
    # combined_list = top_users + top_volunteers
    sorted_list = sorted(top_users, key=lambda x: x['overallScore'], reverse=True)[:10]

    return jsonify(sorted_list)


@app.route('/leaderboard_volunteers', methods=['GET'])
def get_leaderboard_volunteers():
    # Query to fetch top 10 users by point from container_users
    query_users = "SELECT TOP 10 c.name, c.overallScore FROM c ORDER BY c.overallScore DESC"
    top_users = list(container_volunteer.query_items(query=query_users, enable_cross_partition_query=True))

    # # Query to fetch top 10 volunteers by point from container_volunteers
    # query_volunteers = "SELECT c.firstName, c.point FROM c ORDER BY c.point DESC TOP 10"
    # top_volunteers = list(container_volunteer.query_items(query=query_volunteers, enable_cross_partition_query=True))

    # Combine and sort both lists by point, then get the top 10
    # combined_list = top_users + top_volunteers
    sorted_list = sorted(top_users, key=lambda x: x['overallScore'], reverse=True)[:10]

    return jsonify(sorted_list)


def check_blob_exists(blob_service_client, path):
    blob_client = blob_service_client.get_blob_client(container=CONTAINER_NAME_IMAGE, blob=path)
    return blob_client.exists()


def fetch_images_as_path(image_path_without_extension):
    blob_service_client = BlobServiceClient.from_connection_string(CONNECTION_STRING)
    existing_paths = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for i in range(10):
            futures = []
            for ext in EXTENSIONS:
                path = f"{image_path_without_extension}/{i}{ext}"
                future = executor.submit(check_blob_exists, blob_service_client, path)
                futures.append((path, future))
            image_found_for_current_index = False
            for path, future in futures:
                if future.result():
                    full_path = BASE_URL + path
                    existing_paths.append(full_path)
                    image_found_for_current_index = True
                    break
            if not image_found_for_current_index:
                break
    return existing_paths


# def ensure_container_exists(container_name):
#     try:
#         # Create the BlobServiceClient object which will be used to create a container client
#         blob_service_client = BlobServiceClient.from_connection_string(CONNECTION_STRING)
#
#         # Create a unique name for the container (or use the one you've intended to interact with)
#         container_client = blob_service_client.get_container_client(container_name)
#
#         # Create the container if it doesn't exist
#         container_client.create_container()
#
#     except Exception as ex:
#         if ex.error_code == 'ContainerAlreadyExists':
#             print("Container already exists. Proceeding with operations.")
#         else:
#             raise  # An error occurred, the details are in the exception message.


# This method uploads files to the specified container in Azure Blob Storage
def upload_file_to_blob_storage(folder_name, file_stream, filename, file_type='image'):
    try:
        # Create the BlobServiceClient object which will be used to create a container client
        blob_service_client = BlobServiceClient.from_connection_string(CONNECTION_STRING)

        # Set the destination path on the blob storage
        if file_type == 'image':
            blob_name = f"storage/images/{folder_name}/{filename}"  # Path for images
            container_name = CONTAINER_NAME_IMAGE
        elif file_type == 'video':
            blob_name = f"storage/images/{folder_name}/{filename}"  # Path for videos
            container_name = CONTAINER_NAME_IMAGE  # You should define this constant for your video container
        else:
            raise ValueError(f"Unsupported file type: {file_type}")

        # Get the blob client with the provided path
        blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)

        # Upload the content to the blob
        blob_client.upload_blob(file_stream, blob_type="BlockBlob",
                                overwrite=True)  # Overwrite parameter is set to True to allow replacing existing files

    except AzureError as azure_exception:
        print('Exception occurred while handling blob storage:')
        print(azure_exception)
        raise  # Re-throwing the exception, so the caller function can handle it as needed
    except Exception as ex:
        print('An unexpected error occurred:')
        print(ex)
        raise  # Re-throwing this as well, as it's an unexpected state


def convert_image_to_base64(image_file):
    """Convert an image file to a base64 string.

    Args:
    image_file (FileStorage): An image file.

    Returns:
    str: A base64-encoded representation of the image file.
    """
    # Load the image with PIL (Pillow)
    image = Image.open(image_file)
    image_buffer = io.BytesIO()
    image.save(image_buffer, format="JPG")  # You can change the format depending on your image format
    byte_data = image_buffer.getvalue()

    # Encode to base64
    base64_str = base64.b64encode(byte_data).decode('utf-8')
    return base64_str


@app.route('/getCharacter', methods=['GET'])
def get_character():
    try:
        # Extract token and character index from headers or query parameters
        token = request.headers.get("Authorization")
        if token is None or not token.startswith('Bearer '):
            return jsonify(error="Authorization token is required"), 401

        token = token[7:]  # Extract the actual token

        # Query the database to find the user by token
        user_query = f"SELECT * FROM c WHERE c.authToken = '{token}'"
        user_items = list(container_characters.query_items(query=user_query, enable_cross_partition_query=True))

        if not user_items:
            return jsonify(error="User not found"), 404

        user_detail = user_items[0]

        # Get the specific character based on the index
        character = user_detail["characters"]

        return jsonify(character), 200

    except ValueError:
        return jsonify(error="Invalid index provided, must be an integer"), 400

    except Exception as e:
        print(f"An error occurred: {e}")
        return jsonify(error=str(e)), 500


@app.route('/deleteCharacter', methods=['DELETE'])
def delete_character():
    try:
        # Extract token and character index from headers or query parameters
        token = request.headers.get("Authorization")
        if token is None or not token.startswith('Bearer '):
            return jsonify(error="Authorization token is required"), 401

        token = token[7:]  # Extract the actual token
        data = request.get_json()
        character_index = data.get("index")

        if character_index is None:
            return jsonify(error="Character index is required"), 400

        character_index = int(character_index)  # Convert index to integer, you might want to handle ValueError

        # Query the database to find the user by token
        user_query = f"SELECT * FROM c WHERE c.authToken = '{token}'"
        user_items = list(container_characters.query_items(query=user_query, enable_cross_partition_query=True))

        if not user_items:
            return jsonify(error="User not found"), 404

        user_detail = user_items[0]

        # Check if the character exists at the given index
        if "characters" not in user_detail or len(user_detail["characters"]) <= character_index:
            return jsonify(error="Character not found"), 404

        # Remove the character from the list
        del user_detail["characters"][character_index]

        # Update the user document in the database
        container_characters.replace_item(item=user_detail, body=user_detail)

        return jsonify(success=True, message="Character deleted successfully"), 200

    except ValueError:
        return jsonify(error="Invalid index provided, must be an integer"), 400

    except exceptions.CosmosHttpResponseError as e:
        print(f"CosmosDB error: {e.message}")
        return jsonify(error="Database error occurred"), 500

    except Exception as e:
        print(f"An error occurred: {e}")
        return jsonify(error=str(e)), 500


@app.route('/createCharacter', methods=['POST'])
def create_character():
    try:
        # Parse request parameters
        token = request.headers.get("Authorization")
        if token is None or not token.startswith('Bearer '):
            return jsonify(error="Authorization token is required"), 401

        token = token[7:]  # Extract actual token

        data = request.json
        character_name = data.get('character_name')
        character_personality = data.get('character_personality')
        character_role = data.get("character_role")

        if not character_name or not character_personality:
            return jsonify(error="Character name and personality are required"), 400

        # Query the database to find the user by token
        user_query = f"SELECT * FROM c WHERE c.authToken = '{token}'"
        user_items = list(container_characters.query_items(query=user_query, enable_cross_partition_query=True))

        # Check if the user exists, if not, create a new user
        if not user_items:
            user_id = str(uuid.uuid4())  # Create a unique ID for the user
            new_user = {
                'id': user_id,
                'authToken': token,
                'characters': []  # Empty list to hold characters
            }
            # Create a new character object
            new_character = {
                'id': str(uuid.uuid4()),  # Create a unique ID for the character
                'character_name': character_name,
                'character_personality': character_personality,
                "character_role": character_role
            }
            new_user['characters'].append(new_character)

            # Add the new user to the database
            container_characters.create_item(body=new_user)

        else:
            user_detail = user_items[0]

            # Create a new character object
            new_character = {
                'id': str(uuid.uuid4()),  # Create a unique ID for the character
                'character_name': character_name,
                'character_personality': character_personality,
                "character_role": character_role
            }

            # Append the new character to the user's list of characters
            if "characters" in user_detail:
                user_detail["characters"].append(new_character)
            else:
                user_detail["characters"] = [new_character]

            # Replace the user item with the updated information in the Cosmos DB
            container_characters.replace_item(item=user_detail, body=user_detail)

        return jsonify(success=True, message="Character created successfully"), 201

    except exceptions.CosmosHttpResponseError as e:
        print(f"CosmosDB error: {e.message}")
        return jsonify(error="Database error occurred"), 500

    except Exception as e:
        print(f"An error occurred: {e}")
        return jsonify(error=str(e)), 500


def descriptions_to_narrative(frame_descriptions):
    # Initialize an empty list to hold all frame descriptions
    all_descriptions = []

    # Iterate over each frame by its number and description
    for frame_number, description in frame_descriptions.items():
        # If there is a description for the frame, create a sentence for the narrative
        if description:
            # Constructing the sentence for this specific frame
            sentence = f"In frame {frame_number}, {description}."
            # Add the sentence to our list of all descriptions
            all_descriptions.append(sentence)

    # Combine all individual frame descriptions into a single narrative, separated by spaces
    full_narrative = " ".join(all_descriptions)

    return full_narrative


@app.route('/uploadImages', methods=['POST'])
def upload_images():
    token = request.headers.get("Authorization")[7:]
    only_ocr = request.form.get("onlyOcr")
    isCharacter = request.form.get("isCharacter")

    # Initial status
    is_user, is_volunteer = False, False

    date = str(datetime.utcnow()) + " UTC",
    # Create a unique folder name for this upload batch
    folder_name = generate_custom_id()

    # Query the 'users' container
    user_query = f"SELECT * FROM c WHERE c.activeDevice.token = '{token}'"
    user_items = list(container_users.query_items(query=user_query, enable_cross_partition_query=True))
    if user_items:
        is_user = True  # Token is found in users container
        user_detail = user_items[0]  # Extract user details if needed

        # Prepare new post data
        new_post = {
            "name": folder_name,
            "path": f'"users", "{folder_name}"',  # Adjust as needed if this formatting is specific
            "kind": "posts"
        }

        # Append new post to the user's posts list
        if "posts" in user_detail:
            user_detail["posts"].append(new_post)
        else:
            user_detail["posts"] = [new_post]

        # Update the user detail in the database with the new posts list
        container_users.replace_item(item=user_detail["id"], body=user_detail)
        # Create a new post entity in the "posts" container
        # Example data for a post
        post_data = {
            "author": {"name": user_detail["__key__"]["name"],
                       "kind": "user"
                       },
            "date": date,
            "images": {},
            "assignedVolunteer": None,
            "lastResponse": None,
            "resolveTime": None,
            "resolved": None,
            "userAIReview": None,
            "score": None,
            "volunteerReview": None,
            "commercial": "false",
            "userRequest": None,
            "overallScore": None,
            "title": None,
            "volunteerAIReview": None,
            "favorite": False,
            "id": create_uid(),
            "__key__": {
                "name": "",
                "path": "",
                "name": "",
                "kind": "posts"
            }
            # ...
        }
        # create_post_entity(container_posts, post_data)

    # If not found in 'users', check in 'volunteers'
    if not is_user:
        volunteer_query = f"SELECT * FROM c WHERE c.activeDevice.token = '{token}'"
        volunteer_items = list(
            container_volunteer.query_items(query=volunteer_query, enable_cross_partition_query=True))
        if volunteer_items:
            is_volunteer = True  # Token is found in volunteers container
            volunteer_detail = volunteer_items[0]  # Extract volunteer details if needed

            # Prepare new post data
            new_post = {
                "name": folder_name,
                "path": f'"volunteers", "{folder_name}"',  # Adjust as needed if this formatting is specific,
                "kind": "posts"
            }

            # Append new post to the volunteer's posts list
            if "posts" in volunteer_detail:
                volunteer_detail["posts"].append(new_post)
            else:
                volunteer_detail["posts"] = [new_post]

            # Update the volunteer detail in the database with the new posts list
            container_volunteer.replace_item(item=volunteer_detail["id"], body=volunteer_detail)
            # Example data for a post
            post_data = {
                "author": {"name": volunteer_detail["__key__"]["name"],
                           "kind": "volunteer"
                           },
                "date": date,
                "images": {},
                "assignedVolunteer": None,
                "lastResponse": None,
                "resolveTime": None,
                "resolved": None,
                "userAIReview": None,
                "score": None,
                "volunteerReview": None,
                "commercial": "false",
                "userRequest": None,
                "overallScore": None,
                "title": None,
                "volunteerAIReview": None,
                "favorite": False,
                "id": create_uid(),
                "__key__": {
                    "name": "",
                    "path": "",
                    "name": "",
                    "kind": "posts"
                }
                # ...
            }
            # # Create a new post entity in the "posts" container
            # create_post_entity(container_posts, post_data)

            # New dictionaries for images and videos

    ocr_results = {}
    images = {}
    videos = {}
    image_paths = []
    video_paths = []
    image_processing_results = {}
    files = request.files.getlist('images')
    # If user does not select file, browser submits an empty part without filename
    if not files or files[0].filename == '':
        return jsonify(error="No selected file"), 400

    for file in files:
        # Check the MIME type of the file
        if file.content_type not in ALLOWED_MIME_TYPES:
            print(f"File skipped: {file.filename}, unsupported MIME type: {file.content_type}")
            continue  # Skip this file
    # Dictionary to hold image paths and AI comments
    image_info = {}
    openai_instructions = """
                          Apply these steps:

    1: Try to deduct what is happening in the image. Objects relative positions and what objects are present in the image generally can be enough to guess what is happening.
    2: Understand which objects are present in the image. Objects will be expressed with both their color, name(which also has color like in the example) and their position. Try to describe the color of the object to a blind person who never experienced sight.
    3: Try to deduct the place image is taken in, whether it is outdoors or indoors.
    4: Using your interpretation now write a final output. This output must be without a narrator. Which means sentences like "I think, we can deduct" are forbidden and sentence must be structured like "There is a tree on the left side of the picture which appears to be next to a black wearing person".
    5: Using literatural examples try to feel the atmosphere and emotions that the image might have triggered. For example when trees and mountains are present you might output something like "Trees and mountains in the distance create a calming feeling while makes someone feel small". 
    6: Your output is not allowed to have expressions of confirmation like "I will help you/Sure!", or meta knowledge about the chat like "Since this is an ai output/looking at the ai output/since you are a blind person".
    7: Output should be purely description of image re interpreted.
    8: Only send your output description nothing else, not even any /n or any large spaces. I do not want anything other than your description.
    9: Do this description in 150 words.

    Example description:
    In this image, there is a space that creates a pleasant atmosphere. The first thing you notice is a centrally located bench. This bench offers a comfortable seating area and is an ideal spot to watch the events unfolding around it. Standing next to the bench is a person in gray, dressed elegantly. The gray clothing shows that the person has an elegant style.
    The tree on the right side of the picture adds a natural touch to the space. With its lush green leaves and branches, it casts a light shadow. Being near the tree offers a refreshing environment and allows you to feel the beauty of nature.
    It's hard to guess whether this is an indoor or outdoor space, but based on the information provided, it could be an outdoor space. The bench is outdoors and the presence of the tree could suggest an outdoor space.
                      """
    for file in files:
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_extension = filename.rsplit('.', 1)[1].lower()
            base_url = "https://fyestorage.blob.core.windows.net/fye/storage/images/"
            image_paths.append(filename)
            # Distinguish between image and video files
            if file_extension in ['jpg', 'jpeg', 'png']:
                upload_file_to_blob_storage(folder_name, file.stream, filename)  # Image upload
                detection_result = None
                ocr_result = None
                translator = deepl.Translator("d3aa074f-85e5-9a33-ee48-36bc9ace3454:fx")
                target_language = "tr"
                file_url = urljoin(base_url, f"{folder_name}/{filename}")
                try:

                    # If the "onlyOcr" flag is true, we skip object detection and only perform OCR
                    if only_ocr == "true":
                        # Convert image to base64 for object detection
                        image_base64 = convert_image_to_base64(file)
                        ocr_result = ocr(image_base64)  # Assuming 'ocr' is your function to perform OCR
                        ocr_results[file.filename] = ocr_result
                        # Store the AI response along with the image info
                        image_info[filename] = {"imagePath": filename, "aiComment": str(ocr_result[0])}
                        a = 5
                    elif isCharacter == "true":
                        characterIndex = request.form.get("characterIndex")
                        character_query = f"SELECT * FROM c WHERE c.authToken = '{token}'"
                        character_items = list(
                            container_characters.query_items(query=character_query,
                                                             enable_cross_partition_query=True))
                        characterList = character_items[0]["characters"]
                        selectedCharacter = characterList[int(characterIndex)]
                        # or however the character's ID is passed
                        # Assuming a function like this exists
                        if not selectedCharacter:
                            return jsonify(error="Character not found"), 404
                        # Perform object detection (assuming this function exists and returns relevant data)
                        if selectedCharacter:
                            character_name = selectedCharacter['character_name']
                            personality_traits = selectedCharacter[
                                'character_personality']  # e.g., "curious and kind-hearted"
                            character_role = selectedCharacter["character_role"]
                            character_specific_instructions = f"In this image, please provide a description as {character_name}, who has a {personality_traits} personality and role: {character_role}:1: Deduct what is happening in the image using the relative positions of objects and the objects present.2: Describe objects using color, name, and their position as if you're explaining them to a blind person.3: Determine whether the image is indoors or outdoors.4: Provide a final output without a narrator, just like you're telling your friend what you see.5: Use literary examples to convey the atmosphere and emotions the image might trigger.Describe the image in 150 words."
                            detection_result = detect_objects(file_url)
                            # Check if 'objectDescriptions' is in the result and is a list

                            if 'objectDescriptions' in detection_result and isinstance(
                                    detection_result['objectDescriptions'], list):
                                # Object(s) detected, proceed with processing
                                objects_str = ', '.join(
                                    detection_result['objectDescriptions'])  # Joining descriptions

                            # Construct the conversation messages with the AI's initial character-specific instructions and the detection results.
                            chat_messages = [
                                {"role": "system", "content": character_specific_instructions},
                                # Assuming that 'objects_str' is a string of detected objects from the image
                                {"role": "user", "content": f"{objects_str}."}
                            ]
                            ai_response_character = engage_openai(chat_messages)
                            # Create a translation client
                            result = translator.translate_text(ai_response_character, target_lang=target_language)
                            translated_text = result.text
                            image_info[filename] = {"imagePath": filename, "aiComment": translated_text}

                    else:
                        detection_result = detect_objects(file_url)
                        # Check if the result is a dictionary as expected
                        if not isinstance(detection_result, dict):
                            raise TypeError(f"Expected a dictionary, but got {type(detection_result).__name__}")

                        # Check if 'objectDescriptions' is in the result and is a list
                        if 'objectDescriptions' in detection_result and isinstance(
                                detection_result['objectDescriptions'], list):
                            # Object(s) detected, proceed with processing
                            objects_str = ', '.join(detection_result['objectDescriptions'])  # Joining descriptions

                            # Construct the conversation messages with the AI's initial instructions and the detection results.
                            chat_messages = [
                                {"role": "system", "content": openai_instructions},
                                # Make sure openai_instructions is defined
                                {"role": "user", "content": f"{objects_str}."}
                            ]

                            # Generate a response from OpenAI based on the conversation messages.
                            ai_response = engage_openai(
                                chat_messages)  # This is a custom function you'd need to define
                            # Create a translation client
                            result = translator.translate_text(ai_response, target_lang=target_language)
                            translated_text = result.text
                            print(ai_response)

                            # Store the AI response along with the image info
                            image_info[filename] = {"imagePath": filename, "aiComment": translated_text}
                        else:
                            # No objects detected, you might want to handle this scenario differently.
                            image_info[filename] = {"imagePath": filename, "aiComment": ""}

                except Exception as e:
                    print(f"Error in object detection: {e}")

                # If object detection did not find anything, try OCR
                if detection_result is None:
                    try:
                        image_base64 = convert_image_to_base64(file)
                        ocr_result = ocr(image_base64)
                    except Exception as e:
                        print(f"Error in OCR: {e}")

                # Store results keyed by filename to use later when constructing post data
                image_processing_results[filename] = {
                    'detection': detection_result,  # This remains None if no objects were detected
                    'ocr': ocr_result,
                }
            elif file_extension == 'mp4':
                video_paths.append(filename)
                file_url = urljoin(base_url, f"{folder_name}/{filename}")
                upload_file_to_blob_storage(folder_name, file.stream, filename)
                detection_result_video = track_object(file_url)
                translator = deepl.Translator("d3aa074f-85e5-9a33-ee48-36bc9ace3454:fx")
                target_language = "tr"
                if not isinstance(detection_result_video, dict):
                    raise TypeError(f"Expected a dictionary, but got {type(detection_result_video).__name__}")
                detection_result_video = descriptions_to_narrative(detection_result_video)
                prompt = f"""
                    I am providing descriptions from a video analysis for visually impaired individuals. Each description corresponds to different frames and includes objects, their colors, movements, and their bounding box coordinates (x, y, width, height) in a 500x500 frame.

                    Your task is to synthesize this information, not by describing each frame individually, but by summarizing the overall actions, events, and scenes. Interpret the coordinates to describe the general location of objects within the scene as 'top left', 'top right', 'bottom left', or 'bottom right'. Convert these technical details into a comprehensive, smooth narrative that captures the essence of the video without going through it frame by frame. Mention the object's movement direction (if available) and its position in the scene. 

                    The narrative should allow someone without sight to 'visualize' the overarching story or activity taking place in the video. Remember, you're painting a mental picture through a summary, not a segmented, frame-by-frame account.

                    Here are the descriptions:

                    {detection_result_video}

                    For example, if the descriptions indicate various objects like cars and bicycles moving in different directions in several frames, you should narrate:
                    'The scene unfolds with a dynamic rhythm, as vehicles, including a noticeable red car and a blue bicycle, navigate through the space. The car, positioned initially at the upper left, makes a purposeful journey rightward. In contrast, the bicycle appears at the bottom, displaying a contrasting motion to the left. Their movements, seemingly choreographed, portray a city's typical ebb and flow.'

                    Now, please proceed with the provided descriptions and transform them into a summarizing narrative, suitable for a blind audience, making sure to interpret the positions and movements accordingly.
                    """

                # Construct the conversation messages with the AI's initial instructions and the detection results.
                chat_messages = [
                    {"role": "system", "content": prompt},
                    # Make sure openai_instructions is defined
                ]

                # Generate a response from OpenAI based on the conversation messages.
                ai_response = engage_openai(chat_messages)  # This is a custom function you'd need to define
                # Create a translation client
                result = translator.translate_text(ai_response, target_lang=target_language)
                translated_text = result.text
                # Store the AI response along with the image info
                image_info[filename] = {"imagePath": filename, "aiComment": translated_text}
            elif file_extension == 'pdf':
                upload_file_to_blob_storage(folder_name, file.stream, filename)
                full_pdf_text = handle_pdf(file.stream)
                image_info[filename] = {"imagePath": filename, "aiComment": str(full_pdf_text)}

    # Constructing the post data, particularly the 'images' part
    for i, image_path in enumerate(image_paths):
        ai_comment = image_info.get(image_path, {}).get("aiComment", "")
        if image_path in image_processing_results:
            result = image_processing_results[image_path]
            # Set the aiComment based on the results of the detection and OCR
            if result['ocr'] is not None:
                ai_comment = result['ocr']  # Use OCR result as the comment if detection found no objects

        key = f"d_{i}"

        # Extract the file extension
        file_extension = os.path.splitext(image_path)[1].lower()

        # Determine the media type based on the file extension
        if file_extension == '.mp4':
            media_type = "video"
        elif file_extension in ['.png', '.jpg', '.jpeg']:
            media_type = "image"
        elif file_extension == ".pdf":
            media_type = "pdf"
        else:
            media_type = "unknown"  # Default case, you can modify this as needed

        images[key] = {
            "imagePath": "images/" + folder_name + "/" + image_path,
            "media": media_type,  # Add the media type
            "aiComment": ai_comment if ai_comment is not None else "",
            "volunteerComment": ""  # Assuming volunteer comment is added later
        }

    for i, video_path in enumerate(video_paths):
        key = f"v_{i}"
        videos[key] = {
            "videoPath": "videos/" + folder_name + "/" + video_path,
            # Add other video-related fields here
            # "aiComment": ai_comment if ai_comment is not None else "",
            # "volunteerComment": ""  # Assuming volunteer comment is added later
        }

    post_data["images"] = images
    post_data["videos"] = videos
    post_data["__key__"]["name"] = folder_name
    post_data["__key__"]["kind"] = "post"
    post_data["__key__"]["path"] = f'"users", "{folder_name}"'
    create_post_entity(container_posts, post_data)

    return jsonify(success=True, folder_id=folder_name), 201


# def translate_text(text, target_language, subscription_key, endpoint):
#     """
#     Translate the provided text into the target language using Azure's Translator Text API.
#
#     Args:
#     text (str): The text to translate.
#     target_language (str): The language code to translate the text into.
#     subscription_key (str): The Azure Translator Text subscription key.
#     endpoint (str): The Azure Translator Text endpoint URL.
#
#     Returns:
#     str: The translated text.
#     """
#     path = 'translate?api-version=3.0'
#     params = '&to=' + target_language
#     constructed_url = endpoint + path + params
#
#
#
#     headers = {
#         'Ocp-Apim-Subscription-Key': subscription_key,
#         # location required if you're using a multi-service or regional (not global) resource.
#         'Content-type': 'application/json',
#         'X-ClientTraceId': str(uuid.uuid4())
#     }
#
#     # You can customize the body as you see fit, here we're just translating one piece of text.
#     body = [{
#         'text': text
#     }]
#
#     # Make the request
#     request = requests.post(constructed_url, headers=headers, json=body)
#     response = request.json()
#
#     # Extract the translation
#     translated_text = response[0]["translations"][0]["text"] if request.status_code == 200 else None
#
#     return translated_text
# Inside your Flask route or function
def handle_pdf(file_stream):
    file_stream.seek(0)  # Reset file stream position
    pdf = PdfReader(file_stream)
    text_content = []

    for page_num in range(len(pdf.pages)):
        page = pdf.pages[page_num]
        text = page.extract_text()

        if not text:
            try:
                file_stream.seek(0)
                file_bytes = file_stream.read()
                images = convert_from_bytes(file_bytes, first_page=page_num + 1, last_page=page_num + 1)
                if images:
                    image = images[0]
                    buffered = io.BytesIO()
                    image.save(buffered, format="JPEG")
                    image_base64 = base64.b64encode(buffered.getvalue()).decode()

                    ocr_result = ocr(image_base64)
                    text_content.append(ocr_result)
                else:
                    text_content.append("[Error: page could not be converted to image]")
            except Exception as e:
                text_content.append(f"[Error during OCR: {e}]")
        else:
            text_content.append(text)

    full_pdf_text = " ".join(text_content)
    return full_pdf_text


def engage_openai(chat_messages):
    """
    Engage with the OpenAI API based on the provided chat messages to generate a response.
    """
    try:
        # Make sure you've set the OpenAI API key somewhere, usually as an environment variable.
        # You can do it in script as well (though it's not the best practice for production):
        # openai.api_key = 'your-api-key'

        # Construct the prompt from chat messages. We're assuming 'chat_messages' is a list of dictionaries.
        # You should adjust the construction of 'prompt' based on the actual structure of 'chat_messages'.
        # prompt = ''.join([msg['content'] for msg in chat_messages])

        # Call the OpenAI API. Make sure 'model' matches the model/version you're intending to use (e.g., "text-davinci-003").
        # Adjust parameters as necessary for your use case (e.g., "temperature").
        # response = openai.Completion.create(
        #     engine=deployment_name,  # or your specific engine
        #     prompt=prompt,  # we're sending the entire prompt constructed from chat messages
        #     max_tokens=250  # adjust based on how long you expect the response to be
        #     # Add other parameters like 'temperature' as needed
        # )
        completion = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=chat_messages,
            max_tokens=700
        )

        # Extract the text from the OpenAI response. This assumes the response structure has a 'choices' list.
        ai_response = completion["choices"][0]["message"][
            "content"]  # Modify based on the actual structure of your OpenAI response

        return ai_response

    except openai.error.OpenAIError as e:
        # Handle OpenAI-specific errors
        print(f"OpenAI error: {str(e)}")
        return ""  # Return empty string or handle it as per your error management strategy

    except Exception as e:
        # Handle other unexpected errors
        print(f"An unexpected error occurred: {str(e)}")
        return ""  # Return empty string or handle it as per your error management strategy


def detect_objects(image_base64):
    try:
        # Assuming you have an 'object_detection' function set up somewhere that takes a base64 string of an image,
        # performs object detection, and returns the result.
        result = object_detection(image_base64)

        return result  # Depending on how you'll use the result, you might return it directly, jsonify it, etc.

    except Exception as e:
        # Handle exceptions as you see fit here
        print(f"An error occurred: {e}")
        return {'error': str(e)}


def detect_objects_url(image_url):
    try:
        # Assuming you have an 'object_detection' function set up somewhere that takes a base64 string of an image,
        # performs object detection, and returns the result.
        response = requests.get(image_url)
        result = Image.open(BytesIO(response.content)).convert('RGB')
    except Exception as e:
        # Handle exceptions as you see fit here
        print(f"An error occurred: {e}")
        return {'error': str(e)}

    return result  # Depending on how you'll use the result, you might return it directly, jsonify it, etc.


@app.route('/uploadPostScore', methods=['POST'])
def upload_postScore():
    data = request.get_json()
    received_point = data.get("postPoint")
    received_id = data.get("id")
    received_AI = data.get("AI")

    query = "SELECT * FROM c WHERE c.__key__.name = '{}'".format(received_id)
    item_post = list(container_posts.query_items(query=query, enable_cross_partition_query=True))

    if received_AI == "true":
        item_post[0]["userAIReview"] = received_point
        container_posts.upsert_item(item_post[0])
    else:
        item_post[0]["volunteerAIReview"] = received_point
        container_posts.upsert_item(item_post[0])

    return jsonify("Successfully updated!"), 200


@app.route("/uidCheck", methods=["POST"])
def uid_check():
    data = request.get_json()
    received_uid = data.get("uid")
    query = "SELECT * FROM c WHERE c.uid = '{}'".format(received_uid)
    user_post = list(container_users.query_items(query=query, enable_cross_partition_query=True))

    if user_post:
        return jsonify(True)
    else:
        return jsonify(False)


@app.route("/descriptorUpdate", methods=["POST"])
def descriptorUpdate():
    try:
        # Parse data from the received JSON
        data = request.get_json()
        received_postId = data.get("post_id")
        received_images = data.get("images")  # This should be a list of image names

        # Query the database to get the post
        query = f"SELECT * FROM c WHERE c.__key__.name = '{received_postId}'"
        user_posts = list(container_posts.query_items(query=query, enable_cross_partition_query=True))

        if not user_posts:
            return jsonify(success=False, message="No post found with the provided ID"), 404

        # Assuming there's only one post with the given postId, otherwise you need to handle multiple posts
        user_post = user_posts[0]

        descriptor_flag = False  # This flag will determine the value of 'descriptorPosts'

        # Process the 'images' field of the post, comparing with 'received_images' and updating 'descriptorReview' flags
        if 'images' in user_post:
            for key, image_info in user_post['images'].items():
                # Extract the image name from the 'imagePath'
                image_name_with_extension = image_info['imagePath'].split('/')[
                    -1]  # Assuming the name is the last part of the path
                image_name = os.path.splitext(image_name_with_extension)[0]  # Remove the file extension

                # Compare with received images and update the 'sendtoDescriptor' flag
                if image_name in received_images:
                    image_info['sendtoDescriptor'] = True
                    descriptor_flag = True  # If any image is sent to the descriptor, set the flag
                else:
                    image_info['sendtoDescriptor'] = False

            # Set 'descriptorPosts' based on the flag's value after checking all images
            user_post['descriptorPosts'] = descriptor_flag

            # Update the post in the database
            container_posts.upsert_item(user_post)

            return jsonify(success=True, message="Post images updated successfully"), 200
        else:
            return jsonify(success=False, message="'images' field does not exist on the target post"), 400

    except Exception as e:
        # For production code, consider logging the actual error for debugging.
        return jsonify(success=False, message=f"An error occurred while updating the post: {str(e)}"), 500


def fetch_descriptor_images_as_path(image_base_path):
    # Here, we are assuming that 'image_base_path' is the path of the image without the extension
    # and we need to check for each possible extension whether the blob exists.
    blob_service_client = BlobServiceClient.from_connection_string(CONNECTION_STRING)
    existing_paths = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for ext in EXTENSIONS:
            path = f"{image_base_path}{ext}"  # Constructing the full path with each extension
            future = executor.submit(check_blob_exists, blob_service_client, path)
            futures.append((path, future))
        for path, future in futures:
            if future.result():  # If the blob exists, we get the result here
                full_path = BASE_URL + path  # Constructing the full URL
                existing_paths.append(full_path)
                # Assuming we only need one valid path per image base path
                break

    return existing_paths


@app.route("/randomDescriptorImages", methods=["GET"])
def randomDescriptorImages():
    # ... (setup for your Azure Cosmos DB and other initial code remains the same)

    query = "SELECT * FROM c WHERE c.descriptorPosts = true"
    all_images = list(container_posts.query_items(query=query, enable_cross_partition_query=True))

    valid_image_urls = []
    for item in all_images:
        if 'images' in item:
            images = item['images']
            for image in images.values():
                if image.get('sendtoDescriptor'):
                    image_base_path = "storage/" + image['imagePath'].rsplit('.', 1)[0]  # Get path without extension
                    full_image_paths = fetch_descriptor_images_as_path(image_base_path)
                    valid_image_urls.extend(full_image_paths)

    # Selecting up to 4 random image URLs from the list of valid images
    selected_image_urls = random.sample(valid_image_urls, min(len(valid_image_urls), 4))

    # Prepare the response object
    response = {
        "images": selected_image_urls
    }

    return jsonify(response)


# def extract_id(url):
#     """
#     Extracts a unique ID from a URL.
#
#     This function uses a regular expression to identify the alphanumeric ID
#     typically found in URLs. The regular expression looks for a long string
#     of uppercase letters and numbers. This part can be adjusted based on
#     the specific format of the IDs you're working with.
#
#     Parameters:
#     url (str): The URL containing the unique ID.
#
#     Returns:
#     str: The extracted ID.
#     """
#
#     # Regular expression pattern to identify the ID.
#     # This pattern is for IDs consisting of uppercase letters and numbers.
#     # Adjust based on your needs.
#     pattern = r'([A-Z0-9]{20,})'
#
#     # Search for the pattern in the URL
#     match = re.search(pattern, url)
#
#     # If a match is found, return it. Otherwise, return None.
#     if match:
#         return match.group(1)
#     else:
#         return None

@app.route("/responseDescriptor", methods=["POST"])
def responseDescriptor():
    token = request.headers.get("Authorization")[7:]

    data = request.get_json()
    received_image = data.get("images")
    received_text = data.get("text")

    # Extracting the post ID and the image index from the received image URL
    received_image_postId = received_image.split("/")[-2]
    received_imageNameIndex = received_image.split("/")[-1].split(".")[0]

    # Query the database to get the post data based on the post ID
    query = f"SELECT * FROM c WHERE c.__key__.name = '{received_image_postId}'"
    descripterImage_documents = list(container_posts.query_items(query=query, enable_cross_partition_query=True))

    if descripterImage_documents:
        descripterImage = descripterImage_documents[0]

        # Construct the expected image path you want to verify
        expected_image_path = f"images/{received_image_postId}/{received_imageNameIndex}.jpg"

        # Check all images in the 'images' field of the document
        for image_key, image_info in descripterImage.get("images", {}).items():
            if image_info.get("imagePath") == expected_image_path:
                # The image path matches one of the entries in the document
                image_info['volunteerComment'] = received_text
                image_info["sendtoDescriptor"] = False

                # Now, we check if all 'sendtoDescriptor' are False, then we'll update 'descriptorPosts'
                all_sent = all(not img.get("sendtoDescriptor") for img in descripterImage.get("images", {}).values())
                email_query = f'SELECT * FROM c WHERE c.activeDevice.token = "{token}"'
                existing_volunteers = list(container_volunteer.query_items(query=email_query,
                                                                           enable_cross_partition_query=True))  # Enable querying over all logical partitions))

                # Check if the volunteer exists before trying to update
                if existing_volunteers:
                    existing_volunteer = existing_volunteers[0]  # We assume only one matching document

                    # Increment the allTimeDescriptorScore
                    if "allTimeDescriptorScore" in existing_volunteer:
                        existing_volunteer["allTimeDescriptorScore"] += 1  # Update the value in the dictionary
                        existing_volunteer["monthlyDescriptorScore"] += 1
                    else:
                        existing_volunteer["allTimeDescriptorScore"] = existing_volunteer[
                            "allTimeDescriptorScore"]  # In case the property does not exist
                        existing_volunteer["monthlyDescriptorScore"] = existing_volunteer["monthlyDescriptorScore"]

                try:
                    replaced_document = container_volunteer.replace_item(
                        item=existing_volunteer["id"],  # Document ID
                        body=existing_volunteer  # Updated document
                    )
                    print(
                        f'Replaced document: {replaced_document["id"]} with score: {replaced_document["allTimeDescriptorScore"]}')
                # except errors.CosmosHttpResponseError as e:
                #     print(f'An error occurred: {e}')
                except Exception as e:
                    print(f'An error occurred: {e}')
                if all_sent:
                    descripterImage["descriptorPosts"] = False

                try:
                    # Update the document in the database
                    updated_item = container_posts.replace_item(item=descripterImage['id'], body=descripterImage)
                except exceptions.CosmosHttpResponseError as e:
                    return jsonify(success=False, message=f"An error occurred: {e.message}")

                return jsonify(success=True, message="Image path exists in the document.", data=image_info)

        # If the loop completes, the image path was not found in the document
        return jsonify(success=False, message="Image path does not exist in the document.")
    else:
        # Handle the case where no document was found for the provided post ID
        return jsonify(success=False, message="No document found with the provided post ID.")


def closest_colour(requested_colour):
    min_colours = {}
    for key, name in webcolors.CSS3_HEX_TO_NAMES.items():
        r_c, g_c, b_c = webcolors.hex_to_rgb(key)
        rd = (r_c - requested_colour[0]) ** 2
        gd = (g_c - requested_colour[1]) ** 2
        bd = (b_c - requested_colour[2]) ** 2
        rgb_distance = rd + gd + bd
        min_colours[rgb_distance] = name

    # Safeguard here: print to check if there's a non-integer key that crept in
    for key in min_colours.keys():
        if not isinstance(key, int):
            pass

    # Attempt to get the minimum key and return the corresponding color
    try:
        closest_color_key = min(min_colours.keys())
    except Exception as e:
        print(f"Error when finding minimum key in min_colours: {e}")
        print(f"min_colours dictionary keys: {min_colours.keys()}")
        raise  # Raising the exception to stop execution and help in debugging

    return min_colours[closest_color_key]


def get_colour_name(requested_colour):
    try:
        closest_name = actual_name = webcolors.rgb_to_name(requested_colour)
    except ValueError:  # If the color isn't an exact match in the CSS3 list
        closest_name = closest_colour(requested_colour)
        actual_name = None  # No exact name match found

    return closest_name


def object_detection(base64_str):
    # Decode the base64 string
    # Load the YOLOv5 model
    response = requests.get(base64_str)
    image_bytes = io.BytesIO(response.content)
    # Get the class names from YOLOv5 model
    class_names = model.names

    # Load an image from the base64 string
    image_original = Image.open(image_bytes).convert('RGB')
    width, height = image_original.size

    # Perform inference with YOLOv5
    results = model(image_original)

    # Retrieve results
    df = results.pandas().xyxy[0]  # Results as pandas DataFrame

    # Process each detection and create the objects list
    objects = []
    for index, row in df.iterrows():
        class_id = int(row['class'])
        class_name = class_names[class_id]

        # Calculate midpoints of the bounding box
        mid_x = int((row['xmin'] + row['xmax']) / 2)
        mid_y = int((row['ymin'] + row['ymax']) / 2)

        # Get color from the midpoint of the bounding box
        rgb_value = image_original.getpixel((mid_x, mid_y))
        color_name = get_colour_name(rgb_value)

        objects.append({
            "midX": mid_x,
            "midY": mid_y,
            "color": color_name,
            "name": f"{color_name} colored {class_name}",
            # Additional information from the row can be added here as needed
        })

    # Calculate the midpoints for width and height
    mid_width = width // 2
    mid_height = height // 2

    # Define the four grid sectors
    sectors = {
        "top_left": {"x": range(0, mid_width), "y": range(0, mid_height)},
        "top_right": {"x": range(mid_width, width), "y": range(0, mid_height)},
        "bottom_left": {"x": range(0, mid_width), "y": range(mid_height, height)},
        "bottom_right": {"x": range(mid_width, width), "y": range(mid_height, height)}
    }

    # Object descriptions
    object_descriptions = []

    # Determine the sector for each object and create a description
    for image_object in objects:
        x_coord = image_object["midX"]
        y_coord = image_object["midY"]

        for sector_name, ranges in sectors.items():
            if x_coord in ranges["x"] and y_coord in ranges["y"]:
                image_object["grid"] = sector_name
                description = f'"{image_object["name"]}" is located at the "{image_object["grid"]}" of the image.'
                object_descriptions.append(description)
                break

    # Prepare the response
    response = {
        "objectDescriptions": object_descriptions,
        # Include any other relevant information
    }

    return response


def detect_objects_in_frame(frame, model, class_names):
    # Convert the frame from BGR to RGB (as OpenCV uses BGR by default)
    rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

    # Perform inference with YOLO
    results = model(rgb_frame)

    # This next part assumes that 'results' has a specific format. Please adjust based on your actual model output.
    detection_data = results.pandas().xyxy[0]  # Convert results to pandas DataFrame

    frame_objects = []
    for _, row in detection_data.iterrows():
        class_id = int(row['class'])  # Get class ID
        class_name = class_names[class_id]  # Get class name

        # Calculate the midpoint of the bounding box
        mid_x = int((row['xmin'] + row['xmax']) / 2)
        mid_y = int((row['ymin'] + row['ymax']) / 2)

        # Get the color at the midpoint
        color = get_colour_name(
            rgb_frame[mid_y, mid_x])  # This assumes the function 'get_colour_name' is defined elsewhere

        object_data = {
            "name": class_name,
            "bbox": [row['xmin'], row['ymin'], row['xmax'], row['ymax']],  # bounding box
            "color": color
            # ... you can add more attributes as needed
        }
        frame_objects.append(object_data)

    return frame_objects


def ocr(b64_encoded):
    # ocr language settings
    reader_langs = easyocr.Reader(['en', 'tr'])

    # b64 decoder
    im_bytes = base64.b64decode(b64_encoded)
    im_arr = np.frombuffer(im_bytes, dtype=np.uint8)
    img = cv2.imdecode(im_arr, flags=cv2.IMREAD_COLOR)

    # ocr reader
    result = reader_langs.readtext(img, detail=0, paragraph=True)

    return result


def generate_custom_id(length=32):
    """Generate a random string of letters and digits."""
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choice(characters) for i in range(length))


def create_post_entity(container, post_data):
    # Insert the new post entity into the "posts" container
    container.create_item(body=post_data)



def get_post_and_ai_comment(post_id, image_index, question):
    try:
        # Query Azure Cosmos DB to retrieve the post based on post_id
        query = f"SELECT * FROM c WHERE c.__key__.name = '{post_id}'"
        result = list(container_posts.query_items(query, enable_cross_partition_query=True))

        if result:
            # Assuming you have a 'comment' field that stores AI-generated comments
            ai_comment = result[0]["images"]["d_" + image_index]["aiComment"]
            # Concatenate the question and AI commenT
            messages = [
                {"role": "user", "content": f"{ai_comment} {question}"},
            ]
            # Generate a response using ChatGPT
            completion = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=messages,
                max_tokens=700
            )
            # Extract the text from the OpenAI response. This assumes the response structure has a 'choices' list.
            ai_response = completion["choices"][0]["message"][
                "content"]  # Modify based on the actual structure of your OpenAI response

            # Update the aiComment field of the corresponding entity
            if "images" in result[0] and f"d_{image_index}" in result[0]["images"]:
                result[0]["images"][f"d_{image_index}"]["aiComment"] = ai_response

                # Update the Cosmos DB document with the new aiComment
                container_posts.upsert_item(result[0])

            return ai_response  # Return the AI-generated comment
        else:
            return None  # Post not found
    except Exception as e:
        print(f"Error retrieving or updating post: {str(e)}")
        return None



@app.route('/add_comment', methods=['POST'])
def add_comment():
    try:
        data = request.get_json()
        post_id = data.get('post_id')
        image_index = data.get('image_index')
        question = data.get('question')

        # Retrieve the post and AI comment
        post = get_post_and_ai_comment(post_id, image_index, question)
        return jsonify(post)
    except Exception as e:
        return jsonify({"error": str(e)})


def get_direction(prev_bbox, current_bbox):
    """
        Determine the direction of movement based on the change in the bounding box's position.

        :param prev_bbox: Tuple of (x, y, w, h) for the previous bounding box.
        :param current_bbox: Tuple of (x, y, w, h) for the current bounding box.
        :return: String representing the direction of movement.
        """
    # Extract the central points of the previous and current bounding boxes
    prev_x = prev_bbox[0] + (prev_bbox[2] / 2)
    prev_y = prev_bbox[1] + (prev_bbox[3] / 2)
    curr_x = current_bbox[0] + (current_bbox[2] / 2)
    curr_y = current_bbox[1] + (current_bbox[3] / 2)

    # Calculate the change in position
    delta_x = curr_x - prev_x
    delta_y = curr_y - prev_y

    direction = ""

    # Determine the primary direction of movement
    if abs(delta_x) > abs(delta_y):
        if delta_x > 0:
            direction = "right"
        else:
            direction = "left"
    else:
        if delta_y > 0:
            direction = "down"
        else:
            direction = "up"

    return direction


def describe_scene(object_labels, action, direction):
    """
        Create a description of the scene based on the objects, their action, and direction.

        :param object_labels: List of labels of the detected objects.
        :param action: String representing the action of the objects.
        :param direction: String representing the direction of the objects' action.
        :return: String description of the scene.
        """
    # Formulate the descriptive sentence
    description = f"{', '.join(object_labels)} {action} towards the {direction}."

    return description


def track_object(video_url, frame_interval=128):
    # Load the YOLO model. Make sure the model is compatible with the input you're providing.

    # Check if we can access the video stream
    cap = cv2.VideoCapture(video_url)
    if not cap.isOpened():
        print("Error: Could not open video stream.")
        sys.exit()

    class_names = model.names  # Retrieve class names from the model

    # Dictionary to store the descriptions for each frame
    frame_descriptions = {}

    frame_id = 0  # To keep track of the frame count
    prev_objects = {}  # Dictionary to store the previous frame's detected objects and their bounding boxes

    frame_width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    significant_move = frame_width // 4  # A 'significant' move is defined as more than 1/3 the frame's width.

    try:
        while True:
            # Read the next frame from the stream
            ret, frame = cap.read()

            # If we couldn't retrieve a frame, assume we have reached the end of the video
            if not ret:
                break

            if frame_id % frame_interval == 0:
                # Process frame for object detection and get the detections
                objects = detect_objects_in_frame(frame, model, class_names)
                if not objects:
                    frame_id += 1  # Important: We still need to increment frame_id here.
                    continue

                # Create descriptions for each object in the frame
                descriptions = []
                current_objects = {}  # Store current objects for comparison in the next frame

                for obj in objects:
                    obj_id = f"{obj['name']}_{obj['bbox']}"  # Unique identifier for each object based on its class and bounding box
                    current_objects[obj_id] = obj['bbox']

                    if obj_id in prev_objects:
                        # The object was also present in the previous frame. Check if it has moved significantly.
                        prev_bbox = prev_objects[obj_id]
                        current_bbox = obj['bbox']

                        # If the object has moved more than the significant_move threshold, describe the movement
                        if abs(current_bbox[0] - prev_bbox[0]) > significant_move:
                            direction = get_direction(prev_bbox, current_bbox)
                            description = f"A {obj['color']} {obj['name']} moves towards {direction}."
                        else:
                            description = f"A {obj['color']} {obj['name']} is located in {obj['bbox']} of the frame."
                    else:
                        # This is a new object that wasn't in the previous frame.
                        description = f"A {obj['color']} {obj['name']} is located in {obj['bbox']} of the frame."

                    descriptions.append(description)

                # Update the previous objects to the current objects for the next frame's comparison
                prev_objects = current_objects.copy()

                # Add the descriptions for the current frame to our dictionary
                frame_descriptions[str(frame_id // frame_interval)] = ' '.join(
                    descriptions)  # Use 'frame_id // frame_interval' for 2 FPS indexing.

            frame_id += 1  # Move on to the next frame

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        # Clean up and release the video capture resource
        cap.release()
    return frame_descriptions


def check_stream(url):
    try:
        response = requests.get(url, stream=True)
        return response.ok
    except requests.RequestException:
        return False


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
