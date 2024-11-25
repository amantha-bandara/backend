from flask import Blueprint

teachers = Blueprint('teachers', __name__, template_folder='templates')

from . import routes