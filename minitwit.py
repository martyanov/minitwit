# -*- coding: utf-8 -*-
"""
    MiniTwit
    ~~~~~~~~

    A microblogging application written with Flask and sqlite3.

    :copyright: (c) 2010 by Armin Ronacher.
    :license: BSD, see LICENSE for more details.
"""

import os
import time
from hashlib import md5
from datetime import datetime

from flask import Flask, request, session, url_for, redirect, \
     render_template, abort, g, flash
from werkzeug import check_password_hash, generate_password_hash
import redis


# Configuration
REDIS_URL = os.getenv('REDISTOGO_URL', 'redis://localhost:6379')
PER_PAGE = 30
DEBUG = True
SECRET_KEY = 'development key'

# Setup redis client
r = redis.from_url(REDIS_URL)

# Create our little application :)
app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_envvar('MINITWIT_SETTINGS', silent=True)


def get_user(user_id):
    """Get user by username."""
    return r.hgetall('user:%s' % user_id)


def add_user(username, email, password):
    """Add user with the specified credentials."""
    user_id = 'user:%s' % username
    r.hset(user_id, 'username', username)
    r.hset(user_id, 'email', email)
    r.hset(user_id, 'pw_hash',
           generate_password_hash(password))


def get_message(message_id):
    """Get message by id."""
    message = r.hgetall('message:%s' % message_id)
    if message:
        author = get_user(message['author_id'])
        message['email'] = author['email']
        message['username'] = author['username']
    return message


def get_messages(message_ids):
    """Get message list looked up by message ids."""
    messages = []
    for message_id in message_ids:
        messages.append(get_message(message_id))
    return messages

def get_public_timeline_messages():
    """Get public timeline message list."""
    messages = get_messages(r.lrange('timeline', 0, PER_PAGE - 1))
    return messages


def get_user_timeline_messages(user_id):
    """Get user time line message list."""
    message_ids = r.lrange('user:%s:timeline' % user_id, 0, PER_PAGE - 1)
    return get_messages(message_ids)


def add_message_to_public_timeline(message_id):
    """Add message id to public timeline messages list."""
    r.lpush('timeline', message_id)
    r.ltrim('timeline', 0, PER_PAGE - 1)


def add_message_to_user_timeline(user_id, message_id):
    """Add message id to user timeline messages list."""
    followee_ids = get_followees(user_id)
    for followee_id in followee_ids:
        r.lpush('user:%s:timeline' % followee_id, message_id)
    r.lpush('user:%s:timeline' % user_id, message_id)


def push_message(author_id, text):
    """Add message and return its id."""
    _id = r.incr('message_id')
    message_id = 'message:%s' % _id
    r.hset(message_id, 'author_id', author_id)
    r.hset(message_id, 'text', text)
    r.hset(message_id, 'pub_date', time.time())
    return _id


def get_followees(user_id):
    """Get list of user followers."""
    return r.smembers('user:%s:followees' % user_id)

def is_following(user1, user2):
    return r.sismember('user:%s:followees' % user1, user2)


def follow(user1, user2):
    """Follow the specified user."""
    r.sadd('user:%s:followees' % user1, user2)


def unfollow(user1, user2):
    """Unfollow the specified user."""
    r.srem('user:%s:followees' % user1, user2)


def format_datetime(timestamp):
    """Format a timestamp for display."""
    return datetime.utcfromtimestamp(float(timestamp)).strftime('%Y-%m-%d @ %H:%M')


def gravatar_url(email, size=80):
    """Return the gravatar image for the given email address."""
    return 'http://www.gravatar.com/avatar/%s?d=identicon&s=%d' % \
        (md5(email.strip().lower().encode('utf-8')).hexdigest(), size)


@app.before_request
def before_request():
    """Make sure we are connected to the database each request and look
    up the current user so that we know he's there.
    """
    g.user = None
    if 'user_id' in session:
        g.user = get_user(session['user_id'])


@app.route('/')
def timeline():
    """Shows a users timeline or if no user is logged in it will
    redirect to the public timeline.  This timeline shows the user's
    messages as well as all the messages of followed users.
    """
    if not g.user:
        return redirect(url_for('public_timeline'))
    messages = get_user_timeline_messages(g.user['username'])
    return render_template('timeline.html', messages=messages)


@app.route('/public')
def public_timeline():
    """Displays the latest messages of all users."""
    return render_template('timeline.html',
        messages=get_public_timeline_messages())


@app.route('/<username>')
def user_timeline(username):
    """Display's a users tweets."""
    user = get_user(username)
    if not user:
        abort(404)
    followed = False
    if g.user:
        followed = is_following(session['user_id'], username)
    return render_template('timeline.html',
                           messages=get_user_timeline_messages(username),
                           followed=followed,
                           profile_user=user)


@app.route('/<username>/follow')
def follow_user(username):
    """Adds the current user as follower of the given user."""
    if not g.user:
        abort(401)
    user = get_user(username)
    if not user:
        abort(404)
    follow(session['user_id'], username)
    flash('You are now following "%s"' % username)
    return redirect(url_for('user_timeline', username=username))


@app.route('/<username>/unfollow')
def unfollow_user(username):
    """Removes the current user as follower of the given user."""
    if not g.user:
        abort(401)
    user = get_user(username)
    if not user:
        abort(404)
    unfollow(session['user_id'], username)
    flash('You are no longer following "%s"' % username)
    return redirect(url_for('user_timeline', username=username))


@app.route('/add_message', methods=['POST'])
def add_message():
    """Registers a new message for the user."""
    if 'user_id' not in session:
        abort(401)
    if request.form['text']:
        message_id = push_message(session['user_id'], request.form['text'])
        add_message_to_user_timeline(session['user_id'], message_id)
        add_message_to_public_timeline(message_id)
        flash('Your message was recorded')
    return redirect(url_for('timeline'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Logs the user in."""
    if g.user:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        user = get_user(request.form['username'])
        if not user:
            error = 'Invalid username'
        elif not check_password_hash(user['pw_hash'],
                                     request.form['password']):
            error = 'Invalid password'
        else:
            flash('You were logged in')
            session['user_id'] = user['username']
            return redirect(url_for('timeline'))
    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registers the user."""
    if g.user:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        if not request.form['username']:
            error = 'You have to enter a username'
        elif not request.form['email'] or \
                 '@' not in request.form['email']:
            error = 'You have to enter a valid email address'
        elif not request.form['password']:
            error = 'You have to enter a password'
        elif request.form['password'] != request.form['password2']:
            error = 'The two passwords do not match'
        elif get_user(request.form['username']):
            error = 'The username is already taken'
        else:
            add_user(request.form['username'],
                     request.form['email'],
                     request.form['password'])
            flash('You were successfully registered and can login now')
            return redirect(url_for('login'))
    return render_template('register.html', error=error)


@app.route('/logout')
def logout():
    """Logs the user out."""
    flash('You were logged out')
    session.pop('user_id', None)
    return redirect(url_for('public_timeline'))


# Add some filters to jinja
app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.filters['gravatar'] = gravatar_url


if __name__ == '__main__':
    app.run()
