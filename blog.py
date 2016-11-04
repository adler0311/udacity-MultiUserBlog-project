# -*- coding: utf-8 -*-
import os
import re
import hmac
import hashlib
import random
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = "secret"


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


# base setting for blog handler
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
        self.response.headers.add_header('Set-Cookie', 'user_id=;Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


# Main page
class MainPage(BlogHandler):
    def get(self):
        self.render("main.html")


# User Stuff
def make_salt(length=5):
    return "".join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return "%s,%s" % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(",")[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group="default"):
    return db.Key.from_path("users", group)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# blog stuff

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    user = db.ReferenceProperty(User,
                                collection_name='posts')
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    userId = db.IntegerProperty()
    likedBy = db.ListProperty(db.Key)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        counter = len(self.likedBy)
        return render_str("post.html", p=self, counter = counter)


class Comment(db.Model):
    post = db.ReferenceProperty(Post,
                                collection_name='comments')    
    postId = db.IntegerProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    comment = db.StringProperty()
    userId = db.IntegerProperty()

    def render(self):
        username = User.by_id(int(self.userId)).name
        return render_str("comment.html", c=self, username=username)


class BlogFront(BlogHandler):
    def get(self):
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        self.render('front.html', posts=posts)


class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        comments = Comment.all()
        comments.filter("postId =", int(post_id))
        comments.order("-created")

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post, comments=comments, error="")


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect("/blog")

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), subject=subject,
                     content=content,
                     userId=int(self.read_secure_cookie('user_id')),
                     likeCount=0, user = self.user)
            p.put()

            l = Liked(postId=int(p.key().id()), userId=p.userId, liked=False)
            l.put()

            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject,
                        content=content, error=error)


# Unit 2 HW's
class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text=rot13)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


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

        params = dict(username=self.username,
                      email=self.email)

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
        u = User.by_name(self.username)
        if u:
            msg = "That user already exists."
            self.render("signup-form.html", error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect("/blog")


class Login(BlogHandler):
    def get(self):
        self.render("login-form.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect("/blog")
        else:
            msg = "invalid login"
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')


class Unit3Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')


class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username=username)
        else:
            self.redirect('/unit2/signup')


class PostEdit(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if post:
            if self.user:
                if post.userId != int(self.read_secure_cookie('user_id')):
                    error = "This is not yours!"
                    self.render("permalink.html", post=post, comments=post.comments, error=error)
                    return
                self.render('edit.html', subject=post.subject,
                            content=post.content)
            else:
                error = "you have to login first"
                self.render("login-form.html", error=error)
        else:
            error = "There is no post!"
            self.render("permalink.html", post=post, comments=post.comments, error=error)
            return

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if post:
            if self.user:
                if post.userId != int(self.read_secure_cookie('user_id')):
                    error = "This is not yours!"
                    self.render("permalink.html", post=post, comments=post.comments, error=error)
                    return
                else:
                    subject = self.request.get('subject')
                    content = self.request.get('content')

                    if subject and content:
                        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                        post = db.get(key)
                        post.subject = subject
                        post.content = content
                        post.put()
                        self.redirect('/blog/%s' % str(post.key().id()))
                    else:
                        error = "subject and content, please!"
                        self.render("newpost.html", subject=subject, content=content,
                                    error=error)
            else:
                error = "you have to login first"
                self.render("login-form.html", error=error)

        else:
            error = "There is no post!"
            self.render("permalink.html", post=post, comments=post.comments, error=error)
            return



class PostDelete(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if post:
            if self.user:
                if post.userId != int(self.read_secure_cookie('user_id')):
                    error = "This is not yours!"
                    self.render("permalink.html", post=post, comments=post.comments, error=error)
                    return
                self.render('delete.html')
            else:
                error = "you have to login first"
                self.render("login-form.html", error=error)
        else:
            error = "There is no post!"
            self.render("permalink.html", post=post, comments=post.comments, error=error)
            return


    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if post:
            if self.user:
                if post.userId != int(self.read_secure_cookie('user_id')):
                    error = "This is not yours!"
                    self.render("permalink.html", post=post, comments=post.comments, error=error)
                    return
                post.delete()
                self.redirect('/blog')
            else:
                error = "you have to login first"
                self.render("login-form.html", error=error)
        else:
            error = "There is no post!"
            self.render("permalink.html", post=post, comments=post.comments, error=error)
            return


class PostLike(BlogHandler):
    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if post:
            if self.user:
                user_id = int(self.read_secure_cookie('user_id'))

                if int(post.userId) != user_id:
                    if not self.user.key() in post.likedBy:
                        post.likedBy.append(self.user.key())
                        post.put()
                        msg = "you like this post"
                        self.render("permalink.html", post=post, comments=post.comments, error=msg)
                    else:
                        post.likedBy.remove(self.user.key())
                        post.put()
                        msg = "you unlike this post"
                        self.render("permalink.html", post=post, comments=post.comments, error=msg)
                elif int(post.userId) == user_id:
                    error = "you cannot update likes of your own"
                    self.render("permalink.html", post=post, comments=post.comments, error=error)
            else:
                error = "you have to login first"
                self.render("login-form.html", error=error)
        else:
            error = "There is no post!"
            self.render("permalink.html", post=post, comments=post.comments, error=error)
            return


class PostComment(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if post:
            if self.user:
                self.render('newcomment.html', p=post)
            else:
                error = "you have to login first"
                self.render("login-form.html", error=error)
        else:
            self.write("There is no post")

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if post:
            if self.user:
                comment = self.request.get('comments')
                if comment:
                    c = Comment(comment=comment, postId=int(post_id),
                                userId=int(self.read_secure_cookie('user_id')),
                                post=post)
                    c.put()
                    self.redirect('/blog/%s' % post_id)
                else:
                    error = "comment, please!"
                    self.render("newcomment.html", error=error)
            else:
                error = "you have to login first"
                self.render("login-form.html", error=error)
        else:
            error = "There is no post!"
            self.render("permalink.html", post=post, comments=post.comments, error=error)
            return


class CommentEdit(BlogHandler):
    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        c = db.get(key)

        if c:
            if self.user:
                if comment.userId != int(self.read_secure_cookie('user_id')):
                    error = "This is not yours!"
                    self.render("permalink.html", post=post, comments=post.comments, error=error)
                    return
                self.render('commentedit.html', c=comment.comment)
            else:
                error = "you have to login first"
                self.render("login-form.html", error=error)
        else:
            error = "There is no comment!"
            self.render("permalink.html", post=post, comments=post.comments, error=error)
            return


    def post(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        c = db.get(key)

        if c:
            if self.user:
                if comment.userId != int(self.read_secure_cookie('user_id')):
                    error = "This is not yours!"
                    self.render("permalink.html", post=post, comments=post.comments, error=error)
                    return

                comment = self.request.get('comments')
                if comment:
                    c.comment = comment
                    c.put()
                else:
                    error = "subject and content, please!"
                    self.render("newpost.html", subject=subject, content=content,
                                error=error)
            else:
                error = "you have to login first"
                self.render("login-form.html", error=error)
        else:
            error = "There is no comment!"
            self.render("permalink.html", post=post, comments=post.comments, error=error)
            return

class CommentDelete(BlogHandler):
    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        c = db.get(key)

        if c:
            if self.user:
                if c.userId != int(self.read_secure_cookie('user_id')):
                    error = "This is not yours!"
                    self.render("permalink.html", post=post, comments=post.comments, error=error)
                    return
                self.render('commentdelete.html', c=c)
            else:
                error = "you have to login first"
                self.render("login-form.html", error=error)
        else:
            error = "There is no comment!"
            self.render("permalink.html", post=post, comments=post.comments, error=error)
            return

    def post(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        c = db.get(key)

        if c:
            if self.user:
                if c.userId != int(self.read_secure_cookie('user_id')):
                    error = "This is not yours!"
                    self.render("permalink.html", post=post, comments=post.comments, error=error)
                    return                
                post_id = c.postId
                c.delete()
                self.redirect('/blog/%s' % post_id)
            else:
                error = "you have to login first"
                self.render("login-form.html", error=error)
        else:
            error = "There is no comment!"
            self.render("permalink.html", post=post, comments=post.comments, error=error)
            return


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/rot13', Rot13),
                               ('/unit2/signup', Unit2Signup),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/unit3/welcome', Unit3Welcome),
                               ('/blog/edit/([0-9]+)', PostEdit),
                               ('/blog/delete/([0-9]+)', PostDelete),
                               ('/blog/like/([0-9]+)', PostLike),
                               ('/blog/comment/([0-9]+)', PostComment),
                               ('/comment/edit/([0-9]+)', CommentEdit),
                               ('/comment/delete/([0-9]+)', CommentDelete),
                               ],
                              debug=True)
