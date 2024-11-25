from flask import Flask, request, render_template, flash, redirect, url_for, session, abort
from . import teachers

@teachers.route('teachers/registration step')
def register():
    return render_template('teachers/se_te.html')