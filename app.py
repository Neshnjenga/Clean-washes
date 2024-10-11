from flask import Flask,flash,request,render_template,redirect,url_for,session
from flask_mail import Mail,Message
from random import *
import re 
import bcrypt
import pymysql
import secrets
import base64
import time

app=Flask(__name__)
app.secret_key='aesdyiuoiuigyferz'
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT']=465
app.config['MAIL_USERNAME']='chegenelson641@gmail.com'
app.config['MAIL_USE_TSL']=False
app.config['MAIL_USE_SSL']=True

mail=Mail(app)

connection=pymysql.connect(
    host='localhost',
    user='root',
    password='',
    database='flask_cl'
)

cur=connection.cursor()
def sendmail(subject,email,body):
    try:
        msg=Message(subject=subject,sender='chegenelson641@gmail.com',recipients=[email],body=body)
        mail.send(msg)
    except Exception as a:
        print(a)
@app.route('/register',methods=['POST','GET'])
def register():
    if request.method=='POST':
        username=request.form['username']
        email=request.form['email']
        password=request.form['password']
        confirm=request.form['confirm']
        cur.execute('SELECT * FROM fur WHERE username=%s',(username))
        connection.commit()
        data=cur.fetchone()
        cur.execute('SELECT * FROM fur WHERE email=%s',(email))
        connection.commit()
        user=cur.fetchone()
        if username=='' or email=='' or password=='' or confirm=='':
            flash('All fields are required','warning')
            return render_template('register.html',username=username,email=email,password=password,confirm=confirm)
        elif data is not None:
            flash('Create new username','warning')
            return render_template('register.html',username=username,email=email,password=password,confirm=confirm)
        elif user  is not None:
            flash('Create new email','warning')
            return render_template('register.html',username=username,email=email,password=password,confirm=confirm)
        elif username==password:
            flash('Username and password should not be simillar','warning')
            return render_template('register.html',username=username,email=email,password=password,confirm=confirm)
        elif password != confirm:
            flash('Incorrect passwords','warning')
            return render_template('register.html',username=username,email=email,password=password,confirm=confirm)
        elif not re.search('[A-Z]',password):
            flash('Password should have capital letters','warning')
            return render_template('register.html',username=username,email=email,password=password,confirm=confirm)
        elif not re.search('[a-z]',password):
            flash('Paaword should have small letters','warning')
            return render_template('register.html',username=username,email=email,password=password,confirm=confirm)
        else:
            hashed=bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())
            sendAtTime=int(time.time())
            otp=randint(00000,99999)
            cur.execute('INSERT INTO fur(username,email,password,otp,sendAtTime)VALUES(%s,%s,%s,%s,%s)',(username,email,hashed,otp,sendAtTime))
            connection.commit()
            subject='Account creation'
            body=f'Thank you for creating an account with clean washes.\nVerify your account with this otp {otp}'
            sendmail(subject,email,body)
            flash('Account created succesfully please verify','success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/otp',methods=['POST','GET'])
def otp():
    if request.method=='POST':
        id=session['user_id']
        otp=request.form['otp']
        cur.execute('SELECT * FROM fur WHERE id=%s',(id,))
        connection.commit()
        data=cur.fetchone()
        if data is not None:
            if data[7]==int(otp):
                currentTime=int(time.time())
                expiryTime=int(1*60)
                sendAtTime=int(data[10])
                if currentTime - sendAtTime > expiryTime:
                    flash('Otp has expried','warning')
                    return redirect(url_for('otp'))
                else:
                    cur.execute('UPDATE fur SET is_verified=1 WHERE otp=%s',(otp))
                    connection.commit()
                    flash('Account has been verified ','success')
                    return redirect(url_for('login'))
            else:
                flash('Incorrect otp','warning')
                return redirect(url_for('otp'))
    cur.execute('SELECT * FROM fur WHERE id=%s',(session['user_id']))
    connection.commit()
    data=cur.fetchone()
    ResendTime=int(time.time()) - int(data[10])
    remainingTime=int(1*60) - ResendTime
    return render_template('otp.html',remainingTime=remainingTime)

@app.route('/Resend')
def Resend():
    id=session['user_id']
    otp=randint(000000,999999)
    sendAtTime=int(time.time())
    cur.execute('SELECT * FROM fur WHERE id=%s',(id))
    connection.commit()
    data=cur.fetchone()
    cur.execute('UPDATE fur SET otp=%s,sendAtTime=%s WHERE id=%s',(otp,sendAtTime,id))
    connection.commit()
    subject='New otp'
    body=f'This is you new otp {otp}'
    sendmail(subject,data[2],body)
    flash('A new otp has been sent to your email','success')
    return redirect(url_for('otp'))

@app.route('/login',methods=['POST','GET'])
def login():
    if request.method=='POST':
        username=request.form['username']
        password=request.form['password']
        if username=='' or password=='':
            flash('All fields are required','warning')
            return render_template('login.html',username=username,password=password)
        else:
            cur.execute('SELECT * FROM fur WHERE username=%s',(username))
            connection.commit()
            data=cur.fetchone()
            if data is not None:
                if bcrypt.checkpw(password.encode('utf-8'),data[3].encode('utf-8')):
                    session['username']=data[1]
                    session['user_id']=data[0]
                    session['role']=data[4]
                    if data[6]==1:
                            if session['role']=='user':
                                return redirect(url_for('home'))
                            else:
                                return redirect(url_for('home'))
                    else:
                        flash('Please verify your account','warning')
                        return redirect(url_for('otp'))
                else:
                    flash('Incorrect password','warning')
                    return render_template('login.html',username=username,password=password)
            else:
                flash('Incorrect username','warning')
                return render_template('login.html',username=username,password=password)
    return render_template('login.html')

@app.route('/forgot',methods=['POST','GET'])
def forgot():
    if request.method=='POST':
        email=request.form['email']
        cur.execute('SELECT * FROM fur WHERE email=%s',(email))
        data=cur.fetchone()
        if data is not None:
            tokenSend=int(time.time())
            token=secrets.token_hex(50)
            reset_link=url_for('reset',token=token,_external=True)
            cur.execute('UPDATE fur SET token=%s,tokenSend=%s WHERE email=%s',(token,tokenSend,email))
            connection.commit()
            subject='Forgot password'
            body=f'This is your reset link {reset_link}'
            sendmail(subject,email,body)
            flash('A reset link has beem sent to your email ','success')
            return redirect(url_for('forgot'))
        else:
            flash('Incorrect email','warning')
            return redirect(url_for('forgot'))
    return render_template('forgot.html')

@app.route('/reset',methods=['POST','GET'])
def reset():
    if request.method=='POST':
        token=request.args.get('token')
        password=request.form['password']
        confirm=request.form['confirm']
        if password=='' or confirm=='':
            flash('All fields are required','warning')
            return render_template('reset.html',password=password,confirm=confirm)
        elif password != confirm:
            flash('Incorrect passwords','warning')
            return render_template('reset.html',password=password,confirm=confirm)
        elif not re.search('[A-Z]',password):
            flash('Password should have capital letters','warning')
            return render_template('reset.html',password=password,confirm=confirm)
        elif not re.search('[a-z]',password):
            flash('Password should have small letters','warning')
            return render_template('reset.html',password=password,confirm=confirm)
        else:
            cur.execute('SELECT * FROM fur WHERE token=%s',(token))
            connection.commit()
            data=cur.fetchone()
            currentTime=int(time.time())
            expiryTime=int(2*60)
            tokenSend=data[10]
            if currentTime - tokenSend < expiryTime:
                if data is not None:
                    hashed=bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())
                    cur.execute('UPDATE fur SET password=%s,token="token" WHERE token=%s',(hashed,token))
                    connection.commit()
                    flash('Password has been changed','success')
                    return redirect(url_for('login'))
                else:
                    flash('Token is already used','warning')
                    return redirect(url_for('forgot'))
            else:
                flash('Token has expired','warning')
                return redirect(url_for('forgot'))
    return render_template('reset.html')

@app.route('/home')
def home():
    cur.execute('SELECT * FROM fume')
    connection.commit()
    data=cur.fetchall()
    fetch=[]
    for user in data:
        image=user[3]
        decoded=base64.b64encode(image).decode('utf-8')
        upload=list(user)
        upload[3]=decoded
        fetch.append(upload)
    return render_template('home.html',fetch=fetch)


@app.route('/mailsend')
def mailsend():
    return render_template('mail.html')

@app.route('/typemail',methods=['POST','GET'])
def typemail():
    if request.method=='POST':
        subject=request.form['subject']
        body=request.form['body']
        recipient=getUsers()
        html_content=render_template('mailcontent.html',body=body)
        msg=Message(subject=subject,sender='chegenelson641@gmail.com',recipients=recipient)
        msg.html=html_content
        mail.send(msg)
        return redirect(url_for('mailsend'))
    return render_template('typemail.html')

def getUsers():
    cur.execute('SELECT * FROM fur')
    connection.commit()
    data=cur.fetchall()
    return [user[2] for user in data]


@app.route('/add',methods=['POST','GET'])
def add():
    if 'username' in session:
        if session['role']=='admin':
        
            if request.method=='POST':
                name=request.form['name']
                amount=request.form['amount']
                image=request.files['image'].read()
                cur.execute('INSERT INTO fume(name,amount,image)VALUES(%s,%s,%s)',(name,amount,image))
                connection.commit()
                return redirect(url_for('home'))
            return render_template('add.html')
        else:
            return 'You are not allowed'
    else:
        flash('Please login','warning')
        return redirect(url_for('login'))
@app.route('/manage')
def manage():
    if 'username' in session:
        if session['role']=='admin':
            cur.execute('SELECT * FROM fume')
            connection.commit()
            data=cur.fetchall()
            fetch=[]
            for user in data:
                image=user[3]
                decoded=base64.b64encode(image).decode('utf-8')
                upload=list(user)
                upload[3]=decoded
                fetch.append(upload)
                
            return render_template('manage.html',fetch=fetch)
        else:
            return 'You are not allowed'
    else:
        flash('Please login','warning')
        return redirect(url_for('login'))

@app.route('/delete/<id>')
def delete(id):
    if 'username' in session:
        if session['role']=='admin':

            cur.execute('DELETE FROM fume WHERE id=%s',(id))
            connection.commit()
            return redirect(url_for('home'))
        return 'You are not allowed'
    else:
        flash('Please login','warning')
        return redirect(url_for('login'))

@app.route('/update/<id>',methods=['POST','GET'])
def update(id):
    if 'username' in session:
        if session['role']=='admin':
            cur.execute('SELECT * FROM fume WHERE id=%s',(id))
            connection.commit()
            data=cur.fetchone()
            image=data[3]
            decoded=base64.b64encode(image).decode('utf-8')
            if request.method=='POST':
                name=request.form['name']
                amount=request.form['amount']
                image=request.files['image'].read()
                cur.execute('UPDATE fume SET name=%s,amount=%s,image=%s WHERE id=%s',(name,amount,image,id))
                connection.commit()
                return redirect(url_for('home'))
            return render_template('update.html',data=data,decoded=decoded)
        else:
            return 'You are not allowed in this area'
    else:
        flash('Please login','warning')
        return redirect(url_for('login'))
@app.route('/book/<id>',methods=['POST','GET'])
def book(id):
    if 'username' in session:
        user_id=session['user_id']
        if request.method=='POST':
            name=request.form['name']
            phone=request.form['phone']
            email=request.form['email']
            service=request.form['service']
            location=request.form['location']
            address=request.form['address']
            cost=request.form['cost']
            cur.execute('INSERT INTO tip(user_id,name,phone,email,service,location,address,cost)VALUES(%s,%s,%s,%s,%s,%s,%s,%s)',(user_id,name,phone,email,service,location,address,cost))
            connection.commit()
            return redirect(url_for('home'))
            
        else:
            cur.execute('SELECT * FROM fur WHERE id=%s',(user_id))
            connection.commit()
            tap=cur.fetchone()
            cur.execute('SELECT * FROM fume WHERE id=%s',(id))
            connection.commit()
            pie=cur.fetchone()
            return render_template('book.html',pie=pie,tap=tap)
    else:
        flash('Please login','warning')
        return redirect(url_for('login'))

@app.route('/order')
def order():
    if 'username' in session:
            user_id=session['user_id']
            cur.execute('SELECT * FROM tip WHERE user_id=%s',(user_id))
            connection.commit()
            data=cur.fetchall()
            # cur.execute('SELECT * FROM tip WHERE user_id=%s',(user_id))
            # connection.commit()
            # user=cur.fetchone()

            return render_template('orders.html',data=data)
    else:
        flash('Please login','warning')
        return redirect(url_for('login'))

@app.route('/current')
def current():
    if 'username' in session:
        if session['role']=='admin':
            cur.execute('SELECT * FROM tip')
            connection.commit()
            data=cur.fetchall()
            return render_template('current.html',data=data)
        else:
            return 'You are not allowed'
    else:
        flash('Please login','warning')
        return redirect(url_for('login'))

@app.route('/chose/<id>',methods=['POST','GET']) 
def chose(id):
    if 'username' in session:
        if session['role']=='admin':
            cur.execute('SELECT * FROM tip WHERE id=%s',(id))
            connection.commit()
            data=cur.fetchone()
            if request.method=='POST':
                status=request.form['status']
                cur.execute('UPDATE tip SET status=%s WHERE id=%s ',(status,id))
                connection.commit()
                return redirect(url_for('current'))
            return render_template('chose.html',data=data)
        else:
            return 'You are not allowed '
    else:
        flash('Please login','warning')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    if 'username' in session:
        session.clear()
        return redirect(url_for('home'))
    else:
        flash('Please login','warning')
        return redirect(url_for('login'))

        
if __name__ in '__main__':
    app.run(debug=True)

