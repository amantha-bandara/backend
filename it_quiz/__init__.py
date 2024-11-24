# it_quiz/__init__.py

from flask import Blueprint

it_quiz = Blueprint('it_quiz', __name__, template_folder='templates')

# Import routes after initializing the Blueprint
from . import routes
