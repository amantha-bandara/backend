
from flask import Flask, request, render_template, flash, redirect, url_for, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_uploads import UploadSet, configure_uploads, IMAGES
import random
import string
from authlib.integrations.flask_client import OAuth
import logging
from flask_session import Session
from werkzeug.utils import secure_filename

import os
from . import it_quiz







correct_answers = {
    'question1': 'A',  # What does HTML stand for?
    'question2': 'C',  # Which programming language is known as the "mother of all languages"?
    'question3': 'A',  # What is the primary function of the ALU in a computer?
    'question4': 'B',  # Which of these is a programming language?
    'question5': 'A',  # What is the full form of the CPU?
    'question6': 'C',  # Which of the following is used to display web pages?
    'question7': 'A',  # What does CSS stand for?
    'question8': 'B',  # Which of these is the latest version of Python?
    'question9': 'C',  # Which company developed Java?
    'question10': 'A', # Which of these is a markup language?
    'question11': 'B', # Which protocol is used to send emails?
    'question12': 'C', # What is the default port number for HTTP?
    'question13': 'A', # What does SQL stand for?
    'question14': 'C', # Which is an example of a version control system?
    'question15': 'B', # Which of these is an open-source operating system?
    'question16': 'A', # What is the main function of the operating system?
    'question17': 'C', # Which is used to style HTML pages?
    'question18': 'B', # Which language is used for web development along with HTML and CSS?
    'question19': 'A', # What is the primary purpose of an IP address?
    'question20': 'B', # What is the latest version of HTML?
    'question21': 'C', # Which of these is a database management system?
    'question22': 'A', # Which of these is a type of cloud computing?
    'question23': 'B', # Which of the following is a Linux distribution?
    'question24': 'C', # Which of the following is a type of network?
    'question25': 'A', # What is the main function of a database?
}

@it_quiz.route('/quiz')
def quizmain():
    return render_template('quiz/quizmain.html')
@it_quiz.route('/it quiz')
def it():
    return render_template('quiz/itquiz.html')

@it_quiz.route('/it_quiz/score', methods=['GET', 'POST'])
def itscore():
    if request.method == 'POST':
        print("Form submitted via POST!")
        score = 0
        

        for i in range(1, 26):
            user_answer = request.form.get(f'question{i}')
            if user_answer and user_answer.strip() == correct_answers.get(f'question{i}'):
                score += 1


        print(f"Final score: {score}")
        return f'Your score is {score} out of 25.'
    else:
        print("Accessing form via GET request")
        return render_template('quiz/itquiz.html')  
    
    
@it_quiz.route('/it_quiz/back',methods = ['GET'])
def itback():
    return redirect(url_for('it_quiz.quizmain'))