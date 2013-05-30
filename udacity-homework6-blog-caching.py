import os
import webapp2
import jinja2
import hmac
import re
from string import letters
import time
import logging
import json

from google.appengine.ext import db
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

post_key = db.Key.from_path('Blog', 'posts')

SECRET = 'Timur'
def hash_str(s):
    return hmac.new(SECRET, str(s)).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
	val = h.split('|')[0]
	if h == make_secure_val(val):
		return val

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Users(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add = True)



class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class Signup(Handler):
    def get(self):
        self.render("signup.html")


    def post(self):
        have_error = False
        have_user = False
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        params = dict(username=username, email=email)

        """
        user = self.request.cookies.get('user')
        if user:
            user_val = check_secure_val(user)
            if user_val:
                if user.split('|')[0] == username:
                    have_error = True
                    params['user_exists_error'] = "This user is already registered!"
        """
        
        users = Users.all()
        if users.filter("username =", username).get():
            have_error = True
            params['user_exists_error'] = "This user is already registered!"  


        if not valid_username(username):
            params['username_error'] = "You have not entered a valid username!"
            have_error = True
        
        if not valid_password(password):
            params['password_error'] = "You have not entered a valid password!"
            have_error = True
        elif verify != password:
            params['verify_error'] = "Your passwords didn't match!"
            have_error = True

        if not valid_email(email):
            params['email_error'] = "You have not entered a valid email!"
            have_error = True

        if have_error:
            self.render("signup.html", **params)
        else:
            user_cookie_val = make_secure_val(str(username))
            self.response.headers.add_header('Set-Cookie', 'user=%s' % user_cookie_val)

            u = Users(username=username, password=make_secure_val(password), email=email)
            key = u.put()
            
            self.redirect("/welcome")
            
class Login(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        have_error = False
        username = self.request.get("username")
        password = self.request.get("password")
   
        params = dict(username=username)

        users = Users.all()
        user_check = db.GqlQuery("SELECT * FROM Users WHERE username = :1 and password = :2", username, make_secure_val(password))

        if not user_check.get():
            have_error = True
            params['user_error'] = "Incorrect username or password. Try again!"
       
        if have_error == False:
            user_cookie_val = make_secure_val(str(username))
            self.response.headers.add_header('Set-Cookie', 'user=%s' % user_cookie_val)
            self.redirect('/welcome')
        else:
            self.render("login.html", **params)
            

class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user=; Path=/')
        self.redirect("/signup")
        
  
               

class Welcome(Handler):
    def get(self):
        user = self.request.cookies.get('user').split('|')[0]
        if user:
            self.render("welcome.html", user=user)
        else:
            self.redirect("/signup")
        

class Posts(db.Model):
    subject = db.StringProperty(required = True) #the way you create datatypes for an entity in Google Data Store
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True) #Check GDS docs


def top_posts(update = False):
    key = 'top'
    posts = memcache.get(key)
    if posts == [] or update or posts is None:
        logging.error("DB QUERY")
        posts = db.GqlQuery("SELECT * "
                           "FROM Posts "
                           "WHERE ANCESTOR IS :1 "
                           "ORDER BY created DESC "
                           "LIMIT 10",
                          post_key)
         
        posts = list(posts)
        memcache.set(key, posts)
        memcache.set('queried', time.time())
     
    return posts
    
    


class Blog(Handler):
    def render_front(self, subject="", content="", error=""):
        posts = top_posts()
        #db.delete(db.Query(keys_only=True))
        query = memcache.get('queried')
        if query:
            query = int(time.time() - query)
        else:
            query = 0
        if posts:
            self.render("blog.html", subject=subject, content=content, error=error, posts=posts, query=query)
        else:
            self.render("blog.html", subject=subject, content=content, error=error, query=query)


    def get(self):
        user = self.request.cookies.get('user').split('|')[0]
        """if user:
            self.render_front()
        else:
            self.redirect("/signup")
        GET THIS BACK UP TO GET BLOG BACK"""
        self.render_front()
        



class NewPost(Handler):
    def render_front(self, subject="", content="", error=""):
        self.render("newpost.html", subject=subject, content=content, error=error)

    def get(self):
        user = self.request.cookies.get('user').split('|')[0]
        """if user:
            self.render_front()
        else:
            self.redirect("/signup") GET THIS BACK UP TO GET BLOG BACK!!!"""
        self.render_front()

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            p = Posts(parent = post_key, subject = subject, content = content) #creates an obj instance of post
            key = p.put() #stores art obj into database
            
            #time.sleep(1) # sleep for 1 second
            top_posts(True)
            self.redirect("/%d" % key.id())   
        else:
            error = "we need both a subject and some content!"
            self.render_front(subject, content, error)


# Render a single post
class Permalink(Handler):
    def get(self, post_id):
        key = 'POST_' + post_id
        r = memcache.get(key)
        if r:
            post, age = r
            age = int(time.time() - age)
        else:
            post = Posts.get_by_id(int(post_id), parent=post_key)
            save_time = time.time()
            memcache.set(key, (post, save_time))
            age = 0
        self.render("permalink.html", posts = [post], permalink_query = age)



class OutputJson(Handler):
    def get(self):
        self.response.headers.add_header("Content-Type", "application/json")
        posts = Posts.all().fetch(100)
        post_json = []
        for p in posts:
            data = dict()
            data['content'] = p.content
            data['created'] = str(p.created.date())
            data['subject'] = p.subject
	    post_json.append(data)
        self.write(json.dumps(post_json))

class JsonPermalink(Handler):
    def get(self, post_id):
        self.response.headers.add_header("Content-Type", "application/json")
        p = Posts.get_by_id(int(post_id), parent=post_key)
        data = dict()
        data['content'] = p.content
        data['created'] = str(p.created.date())
        data['subject'] = p.subject
        self.write(json.dumps(data))


class FlushCache(Handler):
    def get(self):
        memcache.flush_all()
        self.redirect('/')


app = webapp2.WSGIApplication([('/signup/?', Signup), ('/welcome/?', Welcome), ('/login/?', Login), ('/logout/?', Logout), ('/', Blog), ('/newpost/?', NewPost), ('/(\d+)/?', Permalink), ('/.json/?', OutputJson), ('/(\d+).json/?', JsonPermalink), ('/', Blog), ('/flush', FlushCache)], 
		debug=True)
