from flask import Flask, render_template, request, redirect, url_for, session
import secrets
import uuid

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Store responses temporarily in memory (not persistent)
responses = {}

# Fake form ID to mimic Google Forms
FORM_ID = "1Vczctm8LlOieYFcq3OYBJEkTGUwIl8nqsRu9wSh22kc"

@app.route('/')
def index():
    """Redirect to the form view"""
    return redirect(f'/forms/d/{FORM_ID}/viewform')

@app.route('/forms/d/<form_id>/viewform')
def viewform(form_id):
    """Main form page"""
    return render_template('form.html', form_id=form_id)

@app.route('/forms/d/<form_id>/formResponse', methods=['POST'])
def form_response(form_id):
    """Handle form submission"""
    # Validate the flag
    submitted_flag = request.form.get('entry.1234567890', '').strip()
    correct_flag = 'DSCCTF{4n4ly71c5_3xp053d_2026}'
    
    if submitted_flag != correct_flag:
        # Redirect back to form with error (handled by client-side JS)
        return redirect(f'/forms/d/{form_id}/viewform')
    
    # Generate a fake response ID
    response_id = str(uuid.uuid4())
    
    # Store response in memory (will be lost on restart)
    responses[response_id] = {
        'flag': submitted_flag
    }
    
    # Store response ID in session
    session['response_id'] = response_id
    
    return redirect(f'/forms/d/{form_id}/formResponse?edit2={response_id}')

@app.route('/forms/d/<form_id>/formResponse')
def submitted(form_id):
    """Response submitted confirmation page"""
    response_id = request.args.get('edit2') or session.get('response_id')
    return render_template('submitted.html', response_id=response_id, form_id=form_id)

@app.route('/forms/d/<form_id>/edit')
def edit(form_id):
    """Allow editing responses"""
    response_id = request.args.get('editLink') or session.get('response_id')
    response_data = responses.get(response_id, {})
    return render_template('edit.html', response_id=response_id, data=response_data, form_id=form_id)

@app.route('/forms/d/<form_id>/edit', methods=['POST'])
def update(form_id):
    """Update existing response"""
    response_id = request.form.get('response_id')
    # Update the response (in memory)
    responses[response_id] = {
        'flag': request.form.get('entry.1234567890', '')
    }
    
    session['response_id'] = response_id
    return redirect(f'/forms/d/{form_id}/formResponse?edit2={response_id}')

@app.route('/forms/d/<form_id>/viewanalytics')
def viewanalytics(form_id):
    """Redirect to the real Google Form analytics page with the flag"""
    return redirect('https://docs.google.com/forms/d/1Vczctm8LlOieYFcq3OYBJEkTGUwIl8nqsRu9wSh22kc/viewanalytics')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8015, debug=False)
