
from flask import Blueprint

squiz = Blueprint('squiz', __name__, template_folder='templates')

# Import routes after initializing the Blueprint
from . import routes