from flask import Blueprint, request, render_template, jsonify
from flask_jwt_extended import jwt_required, create_access_token, decode_token
from ..extensions import db, mail
from flask_mail import Message
from ..models import User
import bcrypt

from flask import Flask, render_template, url_for, request, abort #relacao ao metodo de pagamento
import stripe #relacao ao metodo de pagamento


user_api = Blueprint('user_api', __name__)


@user_api.route('/users/', methods=['POST'])
def create():

    data = request.json

    name = data.get('name')
    email = data.get('email')
    idade = data.get('idade')
    password = data.get('password')

    if not name or not email or not password:
        return {'error': 'Dados insuficientes'}, 400

    user_check = User.query.filter_by(email=email).first()

    if user_check:
        return {'error': 'Usuario já cadastrado'}, 400

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    user = User(name=name, email=email, idade=idade,
                password_hash=password_hash)

    db.session.add(user)
    db.session.commit()

    token = create_access_token(identity=user.id)

    msg = Message(sender='fluxo.cce@gmail.com',
                  recipients=[email],
                  subject='Bem Vindo!',
                  html=render_template('email01.html', name=name, token=token))

    mail.send(msg)

    return user.json(), 200


@user_api.route('/users/', methods=['GET'])
# @jwt_required
def index():

    data = request.args

    idade = data.get('idade')

    if not idade:
        users = User.query.all()
    else:

        idade = idade.split('-')

        if len(idade) == 1:

            users = User.query.filter_by(idade=idade[0])
        else:

            users = User.query.filter(
                db.and_(User.idade >= idade[0], User.idade <= idade[1]))

    return jsonify([user.json() for user in users]), 200


@user_api.route('/users/<int:id>', methods=['GET', 'PUT', 'PATCH', 'DELETE'])
# @jwt_required
def user_detail(id):

    user = User.query.get_or_404(id)

    if request.method == 'GET':
        return user.json(), 200

    if request.method == 'PUT':

        data = request.json

        if not data:
            return {'error': 'Requisição precisa de body'}, 400

        name = data.get('name')
        email = data.get('email')

        if not name or not email:
            return {'error': 'Dados insuficientes'}, 400

        if User.query.filter_by(email=email).first() and email != user.email:
            return {'error': 'Email já cadastrado'}, 400

        user.name = name
        user.email = email

        db.session.add(user)
        db.session.commit()

        return user.json(), 200

    if request.method == 'PATCH':

        data = request.json

        if not data:
            return {'error': 'Requisição precisa de body'}, 400

        email = data.get('email')

        if User.query.filter_by(email=email).first() and email != user.email:
            return {'error': 'Email já cadastrado'}, 400

        user.name = data.get('name', user.name)
        user.email = data.get('email', user.email)
        user.idade = data.get('idade', user.idade)

        db.session.add(user)
        db.session.commit()

        return user.json(), 200

    if request.method == 'DELETE':
        db.session.delete(user)
        db.session.commit()

        return {}, 204


@user_api.route('/users/activate/<token>', methods=['GET'])
def activate(token):

    data = decode_token(token)

    user = User.query.get_or_404(data['identity'])

    if user.active == False:
        user.active = True
        db.session.add(user)
        db.session.commit()

    return render_template('email02.html')



#METODO DE PAGAMENTO, AINDA ESTA INCOMPLETO. PRECISA ALINHAR ALGUMAS COISAS COM O FRONT TB


app.config['STRIPE_PUBLIC_KEY'] = 'pk_test_51H7W0FJWsyvl50pz89WI2VTXGEjTqnExVt7HFEPlbSxsly0LOJPtpQG5UbgmDjcDxucPBPkwm6GlMBSSwtFdHS4v00WciCiWj2'
app.config['STRIPE_SECRET_KEY'] = 'sk_test_51H7W0FJWsyvl50pzzqQiKxVn2fV41e1otVJbyYdvnVIlZYq9eSEV1rrenrEZn9tt9jBdpzQKP5gwdbm14mDDkBes004ydJJ7lW'

stripe.api_key = app.config['STRIPE_SECRET_KEY']

@app.route('/')
def index():
    
   
    
    return render_template(
        'index.html', 
        #checkout_session_id=session['id'], 
        #checkout_public_key=app.config['STRIPE_PUBLIC_KEY']
    )

@app.route('/stripe_pay')
def stripe_pay():
     
     session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
            'price': 'price_1H7WaFJWsyvl50pzLQlUKlmQ',
            'quantity': 2,
        }],
        mode='payment',
        success_url=url_for('thanks', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
        cancel_url=url_for('index', _external=True),
    )
    
    return {
        'checkout_session_id': session['id'], 
        'checkout_public_key': app.config['STRIPE_PUBLIC_KEY']
    }

@app.route('/thanks')
def thanks():
    return render_template('thanks.html')

@app.route('/stripe_webhook', methods=['POST'])
def stripe_webhook():
    print('WEBHOOK CALLED')

    if request.content_length > 1024 * 1024:
        print('REQUEST MUITO GRANDE')
        abort(400)
    payload = request.get_data()
    sig_header = request.environ.get('HTTP_STRIPE_SIGNATURE')
    endpoint_secret = 'whsec_Xj8wBk2qiUcjDEmYu5kfkkorJCJ5UUjw'
    event = None

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except ValueError as e:
        # Invalid payload
        print('INVALID PAYLOAD')
        return {}, 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        print('INVALID SIGNATURE')
        return {}, 400

    # Handle the checkout.session.completed event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        print(session)
        line_items = stripe.checkout.Session.list_line_items(session['id'], limit=1)
        print(line_items['data'][0]['description'])

    return {}    