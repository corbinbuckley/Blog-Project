import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'secretword'

# get comment from database using the comments id
def get_comment_by_id(comment_id):
    key = db.Key.from_path('Comment', int(comment_id), parent=comment_key())
    return db.get(key)


def get_post_by_id(post_id):
    key = db.Key.from_path('Post', int(post_id), parent=blog_key())
    return db.get(key)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      self.write('Hello, Udacity!')


##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

def comment_key(name = 'default'):
    return db.Key.from_path('comments',name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    author_id = db.IntegerProperty()
    author_name = db.StringProperty()


    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", Post = self)
        # Changed to Post = self instead of p = self

# Not using this class at the moment. Dont know if I will.
class Comment(db.Model):
    parent_post_id = db.IntegerProperty(required = True)
    comment_id = db.IntegerProperty()
    commenter_id = db.IntegerProperty()
    commenter_name = db.StringProperty()
    comment = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.comment.replace('\n','<br>')
        return render_str('comment.html', c = self)

class BlogFront(BlogHandler):
    def get(self):

        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts = posts)

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        comments = Comment.all().filter('parent_post_id =', int(post_id)).order('-created')
        # comments = c.filter('parent_post_id =', post_id)


        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post, comments = comments)

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')
        author_id = self.user.key().id()
        author_name = self.user.name


        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, author_id = author_id, author_name = author_name)
            p.put()


            #This just shows the one post, maybe could be used to edit or make comments later
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

class EditPost(BlogHandler):
    def get(self, post_id):
        if self.user:

            post = get_post_by_id(post_id)
            #To put the comments in when the error displays
            comments = Comment.all().filter('parent_post_id =', int(post_id))
            if self.user.key().id() == post.author_id:
                subject = post.subject
                content = post.content
                self.render("Edit_post.html", subject = subject, content = content)
            else:
                error_edit = "You can only edit your posts"
                # This doesnt show the comments, see notes on August 4th
                self.render("permalink.html", post = post, error_edit = error_edit, comments = comments)

        else:
            self.redirect('/login')

    def post(self, post_id):
        post = get_post_by_id(post_id)

        if not self.user:
            self.redirect('/blog')
        if self.user.key().id() == post.author_id:
            new_subject = self.request.get('subject')
            new_content = self.request.get('content')

            if new_subject and new_content:
                post.subject = new_subject
                post.content = new_content
                post.put()
                self.redirect('/blog/%s' % str(post.key().id()))
            else:
                error = "Needs subject and content"
                self.render("newpost.html", subject = new_subject, content = new_content, error = error)
        else:
            errror = "You can only edit your posts"
            self.render("permalink.html", post = post, error = error)

class DeletePost(BlogHandler):
    def get(self, post_id):
        if self.user:

            post = get_post_by_id(post_id)
            #To put the comments in when the error displays
            comments = Comment.all().filter('parent_post_id =', int(post_id))
            if self.user.key().id() == post.author_id:
                self.render("delete_post.html", post = post)
            else:
                error_delete = "You can only delete your posts"
                self.render("permalink.html", post = post, error_delete = error_delete, comments = comments)
        else:
            self.redirect('/login')

    def post(self, post_id):
        post = get_post_by_id(post_id)

        if not self.user:
            self.redirect('/blog')
        if post is not None:
            if self.user.key().id() == post.author_id:
                post.delete()
                self.redirect('/blog')
            else:
                error_delete = "You can only delete your posts"
                self.render("permalink.html", post = post, error_delete = error_delete)

# Class to make comments
class NewComment(BlogHandler):
    def get(self, post_id):
        if self.user:
            post = get_post_by_id(post_id)
            self.render("new_comment.html", post = post)

        else:
            self.redirect('/login')

    def post(self, post_id):
        if self.user:
            post = get_post_by_id(post_id)

            comment = self.request.get('comment')
            parent_post_id = int(post_id)
            commenter_id = self.user.key().id()
            commenter_name = self.user.name

            if comment:
                c = Comment(parent=comment_key(),
                            comment = comment,
                            parent_post_id = parent_post_id,
                            commenter_id = commenter_id,
                            commenter_name = commenter_name,
                            comment_id = 1)
                c.put()
                c.comment_id = c.key().id()
                c.put()
                self.redirect('/blog/%s' % str(post.key().id()))
            else:
                error_comment = "You need to write something in order to comment"
                self.render("new_comment.html", error_comment = error_comment, post = post)
        else:
            self.redirect('/login')

class EditComment(BlogHandler):
    """This class will take the oringal comment stuff and display it then take the changes and add it as new commment"""
    def get(self, comment_id):
        if self.user:
            comment = get_comment_by_id(comment_id)
            post = get_post_by_id(comment.parent_post_id)
            if comment is not None and post is not None:
                if self.user.key().id() == comment.commenter_id:
                    comment = comment.comment
                    self.render("edit_comment.html", post = post, comment = comment, comment_id = comment_id)
                else:
                    error_comment = "You can only edit your own comments"
                    self.render('permalink.html', post = post, comment = comment, error_comment = error_comment)
        else:
            self.redirect('/login')

    def post(self, comment_id):
        if self.user:
            comment = get_comment_by_id(comment_id)
            post = get_post_by_id(comment.parent_post_id)
            if comment is not None:
                if self.user.key().id() == comment.commenter_id:
                    new_comment = self.request.get('comment')

                    if new_comment:
                        comment.comment = new_comment
                        comment.put()
                        self.redirect('/blog/%s' % comment.parent_post_id)
                    else:
                        error_comment = "You need to write something in order to comment"
                        self.render("edit_comment.html", post = post, comment = new_comment, error_comment = error_comment)

        else:
            self.redirct('/login')

class DeleteComment(BlogHandler):
    def get(self, comment_id):
        if self.user:
            comment = get_comment_by_id(comment_id)
            post = get_post_by_id(comment.parent_post_id)
            if self.user.key().id() == comment.commenter_id:
                self.render("delete_post.html", post = post)
            else:
                error_delete = "You can only delete your comments"
                self.render("permalink.html", post = post, error_delete = error_delete)
        else:
            self.redirect('/login')

    def post(self, comment_id):
        if self.user:
            comment = get_comment_by_id(comment_id)
            post = get_post_by_id(comment.parent_post_id)
            if self.user.key().id() == comment.commenter_id:
                comment.delete()
                self.redirect('/blog/%s' % comment.parent_post_id)
            else:
                error_delete = "You can only delete your comments"
                self.render("permalink.html", post = post, error_delete = error_delete)

        else:
            self.redirect('/login')




USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Unit2Signup(Signup):
    def done(self):
        self.redirect('/unit2/welcome?username=' + self.username)

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')

class Unit3Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')

class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/unit2/signup')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/signup', Unit2Signup),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/unit3/welcome', Unit3Welcome),
                               ('/blog/edit_post/([0-9]+)', EditPost),
                               ('/blog/delete_post/([0-9]+)', DeletePost),
                               ('/blog/new_comment/([0-9]+)', NewComment),
                               ('/blog/edit_comment/([0-9]+)', EditComment),
                               ('/blog/delete_comment/([0-9]+)', DeleteComment)
                               ],
                              debug=True)
