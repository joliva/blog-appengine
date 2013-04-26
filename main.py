#!/usr/bin/env python

import cgi, re, os, logging
import json, string
import hmac, random
from datetime import datetime

import webapp2, jinja2
from google.appengine.ext import db
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

UNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
UPASS_RE = re.compile(r"^.{3,20}$")
UEMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

COOKIE_SALT = 'KISSMYGRITS'

def valid_username(username):
	return UNAME_RE.match(username)

def valid_password(password):
	return UPASS_RE.match(password)

def valid_email(email):
	return email == "" or UEMAIL_RE.match(email)

def make_salt():
	# salt will be a random six character string
	return ''.join([chr(random.randint(97,122)) for idx in xrange(6)])

def make_password_hash(password):
	if password:
		salt = make_salt()
		return hmac.new(salt, password).hexdigest() + ('|%s' % salt)
	else:
		return None

class Users(db.Model):
	username = db.StringProperty(required = True)
	password_hash = db.StringProperty(required = True)
	email = db.StringProperty()
	created = db.DateTimeProperty(auto_now_add = True)

	@staticmethod
	def get_user(username):
		user = None
		if username:
			qry = "SELECT * FROM Users WHERE username = '%s'" % username
			#logging.info('query = %s', qry)
			user = db.GqlQuery(qry).get()
		return user

	@staticmethod
	def create_user(user):
		# assumes properties of user were previously validated
		if user:
			user = Users(**user)
			key = user.put()		

class BlogPost(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

class Handler(webapp2.RequestHandler):
	global posts_stale

	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def create_cookie(self, value):
		# cookie format: value|salted hash
		if value:
			return '%s|' % value + hmac.new(COOKIE_SALT, value).hexdigest()
		else:
			return None

	def store_cookie(self, key, value):
		if key and value:
			self.response.set_cookie(key, value=self.create_cookie(value), path='/')

	def remove_cookie(self, key):
		if key:
			self.response.set_cookie(key, value='', path='/')
			#self.response.delete_cookie(key)

	def get_cookie(self, key):
		# cookie format: value|salted hash
		if key:
			hashed_value = self.request.cookies.get(key)

			if hashed_value:
				value, salted_hash = hashed_value.split('|')
				if hashed_value == ('%s|' % value) + hmac.new(COOKIE_SALT, value).hexdigest():
					return value
		return None

	def blog_entries_to_json(self, entrylist):
		# make list of dictionaries
		lst = []
		for entry in entrylist:
			d = {}
			d['subject'] = entry.subject.encode('ascii','ignore')
			d['content'] = entry.content.encode('ascii','ignore')
			d['created'] = entry.created.ctime()
			d['last_modified'] = entry.last_modified.ctime()
			lst.append(d)

		out_json = json.dumps(lst)
		return out_json

class Signup(Handler):
	def get(self):
		self.render('signup.html')

	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")
		verify = self.request.get("verify")
		email = self.request.get("email")
		err_name=""
		err_pass=""
		err_vpass=""
		err_email=""
		err = False

		if not valid_username(username):
			err_name = "That's not a valid username."
			err = True

		if Users.get_user(username) != None:
			err_name = "That user already exists"
			err = True

		if not valid_password(password):
			password=""
			verify=""
			err_pass = "That's not a valid password."
			err = True
		elif verify != password:
			password=""
			verify=""
			err_vpass = "Your passwords didn't match."
			err = True

		if not valid_email(email):
			err_email = "That's not a valid email."
			err = True

		if err == True:
			args = {"username":username, "password":password, "verify":verify, "email":email, "err_name":err_name, "err_pass":err_pass, "err_vpass":err_vpass, "err_email":err_email}
			self.render('signup.html', **args)
		else:
			# save new user into DB
			user = {}
			user['username'] = username
			user['password_hash'] = make_password_hash(password)
			user['email'] = email
			Users.create_user(user)

			# save login session cookie
			self.store_cookie('username', username)

			self.redirect('/blog/welcome')

class Login(Handler):
	def get(self):
		self.render('login.html')

	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")
		err = False

		if username and password:
			# validate login credentials
			user = Users.get_user(username)
			if user:
				# password hash: hmac.new(salt, password).hexdigest() + '|' + salt
				password_hash = user.password_hash.encode('ascii')
				logging.info('password_hash = %s', password_hash)
				hashval, salt = password_hash.split('|')
				logging.info('hashval = %s  salt=%s', hashval, salt)

				if hashval == hmac.new(salt, password).hexdigest():
					# save login session cookie
					self.store_cookie('username', username)
					self.redirect('/blog/welcome')
					return

		args = {"username":username, "password":password, "error":'Invalid Login'}
		self.render('login.html', **args)

class Logout(Handler):
	def get(self):
		self.remove_cookie('username')
		self.redirect('/blog/signup')

class Welcome(Handler):
	def get(self):
		# get session cookie and validate, if bogus redirect to signup page
		username = self.get_cookie('username')
		if username:
			self.render('welcome.html', username=username)
		else:
			self.redirect('/blog/signup')

class BlogFront(Handler):
	def warm_cache(self):
		posts = db.GqlQuery("SELECT * FROM BlogPost ORDER BY created DESC LIMIT 10")

		# regenerate HTML and JSON and store in cache
		out_json = self.blog_entries_to_json(posts)
		out_html = self.render_str('front.html', posts=posts)
		logging.info('insert front_json into cache')
		memcache.set('front_json', {'cached_time':datetime.now(), 'content':out_json})
		logging.info('insert front_html into cache')
		memcache.set('front_html', {'cached_time':datetime.now(), 'content':out_html})

	def get(self, suffix=''):
		global posts_stale

		if posts_stale == True:
			self.warm_cache()
			posts_stale = False

		if suffix == '.json':
			value = memcache.get('front_json')
			self.response.headers['Content-Type'] = 'application/json, charset=UTF-8'
		else:
			value = memcache.get('front_html')

			now = datetime.now()
			delta_secs = (now - value['cached_time']).seconds
			footer = '<div class=footer>&copy; Copyright 2012 by <a href="http://olivalabs.com">Oliva Labs</a>.</div>'
			footer += '<div class="age">Queried %s seconds ago</div>' % delta_secs

			value['content'] = string.replace(value['content'], 'XXYYZZ', footer)

		if not value:
			# this might be necessary if memcache purges these entries
			self.warm_cache()

		self.write(value['content'])

class Post(Handler): 
	def warm_cache(self, post_id):
		post = BlogPost.get_by_id(int(post_id))

		# regenerate HTML and JSON and store in cache
		out_json = self.blog_entries_to_json([post])
		out_html = self.render_str('post.html', post=post)
		logging.info('insert post_json into cache')
		memcache.set('%s_json' % post_id, {'cached_time':datetime.now(), 'content':out_json})
		logging.info('insert post_html into cache')
		memcache.set('%s__html' % post_id, {'cached_time':datetime.now(), 'content':out_html})

	def get(self, post_id, suffix=''):
		global posts_stale

		value = memcache.get('%s_json' % post_id)
		if value == None:
			self.warm_cache(post_id)

		if suffix == '.json':
			value = memcache.get('%s_json' % post_id)
			self.response.headers['Content-Type'] = 'application/json, charset=UTF-8'
		else:
			value = memcache.get('%s__html' % post_id)

			now = datetime.now()
			delta_secs = (now - value['cached_time']).seconds
			footer = '<div class=footer>&copy; Copyright 2012 by <a href="http://olivalabs.com">Oliva Labs</a>.</div>'
			footer += '<div class="age">Queried %s seconds ago</div>' % delta_secs

			value['content'] = string.replace(value['content'], 'XXYYZZ', footer)

		if not value:
			# this might be necessary if memcache purges these entries
			self.warm_cache(post_id)

		self.write(value['content'])

class NewPost(Handler):
	def get(self):
		self.render_front('newpost.html', error='')

	def post(self):
		global posts_stale

		# validate fields
		subject = self.request.get('subject')
		content = self.request.get('content')
		if subject and content:
			# insert new post into datastore
			p = BlogPost(subject = subject, content=content)
			key = p.put()
			posts_stale = True

			# redirect to post permalink
			self.redirect('/blog/' + str(key.id()))
		else:
			self.render_front('newpost.html', subject=subject, content = content, error='subject and content are required')

	def render_front(self, template, subject='', content='', error=''):
		self.write(self.render_str(template,  subject=subject, content=content, error=error))

class Flush(Handler):
	def get(self):
		global posts_stale

		memcache.flush_all()
		posts_stale = True
		#self.redirect('/blog')

posts_stale = True

routes = [
	('/blog', BlogFront),
	('/blog/?(\.json)', BlogFront),
	('/blog/newpost/?', NewPost),
	('/blog/(\d+)', Post),
	('/blog/(\d+)(\.json)', Post),
	('/blog/signup/?', Signup),
	('/blog/welcome/?', Welcome),
	('/blog/login/?', Login),
	('/blog/logout/?', Logout),
	('/blog/flush/?', Flush)
]

app = webapp2.WSGIApplication(routes, debug=True)

