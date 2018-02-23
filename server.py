#import all my stuff

import md5				# for passwords
import os, binascii		# for salts
import datetime			# used for checking if the post is older than 30 min
from flask import Flask, render_template, request, redirect, session, flash
app = Flask(__name__)
app.secret_key = 'jkfu890342htruo34v7yut8039pthjiopv78t0432-y5t3480wtb342y905n34um20w'

#sql connection
from mysqlconnection import MySQLConnector
mysql = MySQLConnector(app, 'the_wall_db')

# for email verification
import re
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')



# root route
@app.route('/')
def index():
	# if user is already logged in, go right to the members page
	if session.get('id') != None:
		return redirect('/members')

	return render_template('index.html')

# renders registration page
@app.route('/sign_up')
def sign_up():
	return render_template('register.html')

# validates and adds the new user to the db
@app.route('/register', methods=['POST'])
def register():
	first_name = request.form['first_name']
	last_name = request.form['last_name']
	email = request.form['email']
	password = request.form['password']
	confirm_pw = request.form['confirm_pw']

	first_name_valid = False
	last_name_valid = False
	email_valid = False
	password_valid = False
	passwords_match = False

	# check if email already exists in db
	query = "SELECT * FROM users WHERE email_address=:email_address"
	data = {'email_address': email}

	result = mysql.query_db(query, data)

	if len(result) != 0:
		flash("User already exists.", 'error')
		return redirect("/sign_up")

	# validate first_name
	if len(first_name) > 1 and first_name.isalpha():
		first_name_valid = True
	else:
		if len(first_name < 2):
			flash("First Name must be 2 or more letters.", 'error')
		if not first_name.isalpha():
			flash("First Name can only be letters.", 'error')

	# validate last_name
	if len(last_name) > 1 and last_name.isalpha():
		last_name_valid = True
	else:
		if len(first_name < 2):
			flash("First Name must be 2 or more letters.", 'error')
		if not first_name.isalpha():
			flash("First Name can only be letters.", 'error')

	# validate email
	if EMAIL_REGEX.match(email):
		email_valid = True
	else:
		flash('Must submit a valid email address.', 'error')

	# validate password
	if len(password) > 7 and not password.isalpha():
		password_valid = True
	else:
		if len(password) < 8:
			flash("Password must be at least 8 characters", 'error')
		if password.isalpha():
			flash("Password must containe 1 number or special character", 'error')

	# check if passwords match
	if password == confirm_pw:
		passwords_match = True
	else: 
		flash("Passwords must match.", 'error')


	# if everything is valid, register new user
	if first_name_valid and last_name_valid and email_valid and password_valid and passwords_match:
		# register user
		salt = binascii.b2a_hex(os.urandom(15))
		query = "INSERT INTO users (first_name, last_name, email_address, password, salt, created_at, updated_at) VALUES (:first_name, :last_name, :email_address, :password, :salt, NOW(), NOW())"
		data = {
				'first_name': first_name,
				'last_name': last_name,
				'email_address': email,
				'password': md5.new(password + salt).hexdigest(),
				'salt': salt
		}
		mysql.query_db(query, data)

		query = "SELECT id, first_name FROM users WHERE first_name=:first_name AND last_name=:last_name AND email_address=:email_address"
		data = {
				'first_name': first_name,
				'last_name': last_name,
				'email_address': email
		}
		user = mysql.query_db(query, data)
		session.clear()
		session['id'] = user[0]['id']
		session['first_name'] = user[0]['first_name']
		return redirect('/members')
	else:
		return redirect('/sign_up')


	return redirect('/')


# validates the user trying to log in, and sends them to the members page.
@app.route('/login', methods=['POST'])
def login():
	email = request.form['email']
	password = request.form['password']

	query = "SELECT * FROM users WHERE users.email_address=:email_address LIMIT 1"
	data = {'email_address': email}
	user = mysql.query_db(query, data)
	

	if len(user) != 0:
		hashed_pw = md5.new(password + user[0]['salt']).hexdigest()
		if user[0]['password'] == hashed_pw:
			session.clear()
			session['id'] = user[0]['id']
			session['first_name'] = user[0]['first_name']
			return redirect('/members')
		else:
			flash('Incorrect password', 'error')
	else:
		flash('User does not exists.', 'error')

	return redirect('/')


# the actual members page
@app.route('/members')
def members():

	#check if someone is logged in, if not, boot them out.
	if session.get('id') == None:
		return redirect('/')

	# pull all the messages from the db
	query = """SELECT messages.id, messages.user_id, CONCAT(users.first_name, ' ', users.last_name) as posted_by, DATE_FORMAT(messages.created_at, '%M %D, %Y') as posted_on, messages.message as content 
				FROM messages
				JOIN users ON messages.user_id = users.id
				ORDER BY messages.created_at DESC
			"""
	messages = mysql.query_db(query)


	# pull all the comments from the db
	query = """SELECT comments.id, comments.user_id, comments.message_id, CONCAT(users.first_name, ' ', users.last_name) as posted_by, DATE_FORMAT(messages.created_at, '%M %D, %Y') as posted_on, comments.comment as content 
				FROM comments
				JOIN messages ON comments.message_id = messages.id
				JOIN users ON messages.user_id = users.id
			"""
	comments = mysql.query_db(query)

	return render_template('members.html', messages=messages, comments=comments)


# saves the new message to the db
@app.route('/new_message', methods=['POST'])
def new_message():
	user_id = session['id']
	message = request.form['message']

	query = "INSERT INTO messages (user_id, message, created_at, updated_at) VALUES (:user_id, :message, NOW(), NOW())"
	data = {
		'user_id': user_id,
		'message': message
	}

	mysql.query_db(query, data)

	return redirect('/members')

# saves the new comment to the db
@app.route('/new_comment/<message_id>', methods=['POST'])
def new_comment(message_id):
	user_id = session['id']
	comment = request.form['comment']

	query = "INSERT INTO comments (message_id, user_id, comment, created_at, updated_at) VALUES (:message_id, :user_id, :comment, NOW(), NOW())"
	data = {
		'message_id': message_id,
		'user_id': user_id,
		'comment': comment
	}

	mysql.query_db(query, data)

	return redirect('/members')

# deletes a message and all comments realted to it.
@app.route('/delete_message/<message_id>')
def delete_message(message_id):
	query = "SELECT messages.user_id, messages.created_at FROM messages WHERE id=:id"
	data = {'id': int(message_id)}

	result = mysql.query_db(query, data)
	message_user_id = result[0]['user_id']
	created_at = result[0]['created_at']


	# make sure the user is deleting their own message, and if the message is older than 30 min
	if message_user_id == session['id'] and created_at > datetime.datetime.now()-datetime.timedelta(minutes=30):
		query = "DELETE FROM messages WHERE messages.id=:id"
		mysql.query_db(query, data)
		
		#deletes all the comments for that post if any exists
		query = "SELECT * FROM comments WHERE comments.message_id=:id"
		if len(mysql.query_db(query,data)) != 0:
			query = "DELETE FROM comments WHERE comments.message_id=:id"
			mysql.query_db(query, data)

		flash("Message Deleted.", 'success')
	else:
		flash("You don't have permission to delete that message.", 'error')

	return redirect('/members')


# deletes a comment
@app.route('/delete_comment/<comment_id>')
def delete_comment(comment_id):
	query = "SELECT comments.user_id, comments.created_at FROM comments WHERE id=:id"
	data = {'id': int(comment_id)}

	result = mysql.query_db(query, data)
	comment_user_id = result[0]['user_id']
	created_at = result[0]['created_at']

	# make sure the user is deleting their own comment and check if the comment is older than 30 min
	if comment_user_id == session['id'] and created_at > datetime.datetime.now()-datetime.timedelta(minutes=30):
		query = "DELETE FROM comments WHERE comments.id=:id"
		data = {'id': int(comment_id)}
		mysql.query_db(query, data)
		flash("Comment Deleted.", 'success')
	else:
		flash("You don't have permission to delete that comment.", 'error')

	return redirect('/members')


#logs the current user out.
@app.route('/logout')
def logout():
	session.clear()
	return redirect('/')





app.run(debug=True)








