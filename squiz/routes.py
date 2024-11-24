from flask import Flask, request, render_template, flash, redirect, url_for, session, abort
from . import squiz

correct_answers = {
    'question1': 'A',
    'question2': 'A',
    'question3': 'A',
    'question4': 'A',
    'question5': 'A',
    'question6': 'A',
    'question7': 'A',
    'question8': 'A',
    'question9': 'A',
    'question10': 'A',
    'question11': 'A',
    'question12': 'A',
    'question13': 'A',
    'question14': 'A',
    'question15': 'A',
    'question16': 'A',
    'question17': 'B',
    'question18': 'A',
    'question19': 'B',
    'question20': 'A',
    'question21': 'A',
    'question22': 'A',
    'question23': 'A',
    'question24': 'A',
    'question25': 'A'
}





@squiz.route('/squiz/main')
def sciequiz():
    return render_template('squiz/squiz.html')

@squiz.route('/squiz/score', methods=['GET', 'POST'])
def scienscore():
    if request.method == 'POST':
        
        score = 0
        

        for i in range(1, 26):
            user_answer = request.form.get(f'question{i}')
            if user_answer and user_answer.strip() == correct_answers.get(f'question{i}'):
                score += 1
        



        print(f"Final score: {score}")
        return f'Your score is {score} out of 25.'
    else:
        print("Accessing form via GET request")
        return render_template('squiz/squiz.html')  