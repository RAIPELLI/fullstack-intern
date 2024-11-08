from flask import Blueprint, render_template, request, redirect, url_for, flash
from models import db, User, Software, AccessRequest
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash

main = Blueprint('main', __name__)

@main.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.create_user(username, password)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully.', 'success')
        return redirect(url_for('main.login'))
    return render_template('signup.html')

@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.role == 'Employee':
                return redirect(url_for('main.request_access'))
            elif user.role == 'Manager':
                return redirect(url_for('main.pending_requests'))
            elif user.role == 'Admin':
                return redirect(url_for('main.create_software'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('login.html')

@main.route('/create_software', methods=['GET', 'POST'])
@login_required
def create_software():
    if current_user.role != 'Admin':
        return redirect(url_for('main.login'))
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        access_levels = request.form.getlist('access_levels')
        software = Software(name=name, description=description, access_levels=",".join(access_levels))
        db.session.add(software)
        db.session.commit()
        flash('Software created successfully.', 'success')
        return redirect(url_for('main.create_software'))
    return render_template('create_software.html')

@main.route('/request_access', methods=['GET', 'POST'])
@login_required
def request_access():
    if current_user.role != 'Employee':
        return redirect(url_for('main.login'))
    if request.method == 'POST':
        software_id = request.form.get('software_id')
        access_type = request.form.get('access_type')
        reason = request.form.get('reason')
        request_access = AccessRequest(user_id=current_user.id, software_id=software_id, access_type=access_type, reason=reason)
        db.session.add(request_access)
        db.session.commit()
        flash('Access request submitted successfully.', 'success')
        return redirect(url_for('main.request_access'))
    software_list = Software.query.all()
    return render_template('request_access.html', software_list=software_list)

@main.route('/pending_requests')
@login_required
def pending_requests():
    if current_user.role != 'Manager':
        return redirect(url_for('main.login'))
    requests = AccessRequest.query.filter_by(status='Pending').all()
    return render_template('pending_requests.html', requests=requests)

@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))
