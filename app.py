from flask import Flask, render_template, flash, redirect, url_for, request, abort, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_bcrypt import Bcrypt
from functools import wraps
from dotenv import load_dotenv
from flask_wtf.file import FileField, FileAllowed, FileRequired
from werkzeug.utils import secure_filename
import os
import requests
import logging


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)

app.config['WTF_CSRF_CHECK_DEFAULT'] = False

load_dotenv()
app.config['API_KEY'] = (
        os.getenv('API_KEY') or
        os.environ.get('API_KEY') or
        'your-secret-api-key-here'
)
app.config['SECRET_KEY'] = os.urandom(24).hex()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.dirname(__file__), 'site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['YANDEX_MAPS_API_KEY'] = '5edfcff0-94a7-4c66-bbc0-f743141f39c6'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
csrf = CSRFProtect(app)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    avatar = db.Column(db.String(100))
    favorites = db.relationship('Favorite', backref='user', lazy=True)


class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    coordinates = db.Column(db.String(50), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Подтвердите пароль', validators=[DataRequired(), EqualTo('password')])
    avatar = FileField('Аватарка',
                       validators=[FileAllowed(['jpg', 'png', 'jpeg'], 'Только изображения JPG, PNG или JPEG!')
                                   ])
    submit = SubmitField('Зарегистрироваться')


class LoginForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')


class SearchForm(FlaskForm):
    query = StringField('Поиск адреса', validators=[DataRequired()])
    show_postcode = BooleanField('Показывать почтовый индекс')
    submit = SubmitField('Искать')
    reset = SubmitField('Сбросить')


def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.headers.get('X-API-KEY') != app.config['API_KEY']:
            return jsonify({'error': 'Invalid API key'}), 401
        return f(*args, **kwargs)

    return decorated_function


@app.route('/api/users/<int:user_id>', methods=['GET'])
@api_key_required
def api_get_user(user_id):
    user = User.query.get_or_404(user_id)
    return jsonify({
        'id': user.id,
        'username': user.username,
        'favorites_count': len(user.favorites)
    })


@app.route('/api/favorites', methods=['GET'])
@api_key_required
def api_get_favorites():
    if not request.headers.get('X-USER-ID'):
        return jsonify({'error': 'User ID required'}), 400

    user_id = int(request.headers.get('X-USER-ID'))
    user = User.query.get_or_404(user_id)

    favorites = [{
        'id': fav.id,
        'address': fav.address,
        'coordinates': fav.coordinates
    } for fav in user.favorites]

    return jsonify(favorites)


@app.route('/api/favorites', methods=['POST'])
@api_key_required
def api_add_favorite():
    if not request.headers.get('X-USER-ID'):
        return jsonify({'error': 'User ID required'}), 400

    data = request.get_json()
    if not data or not data.get('address') or not data.get('coordinates'):
        return jsonify({'error': 'Address and coordinates required'}), 400

    user_id = int(request.headers.get('X-USER-ID'))
    user = User.query.get_or_404(user_id)

    existing = Favorite.query.filter_by(
        user_id=user_id,
        coordinates=data['coordinates']
    ).first()

    if existing:
        return jsonify({'error': 'Address already in favorites'}), 400

    fav = Favorite(
        user_id=user_id,
        address=data['address'],
        coordinates=data['coordinates']
    )
    db.session.add(fav)
    db.session.commit()

    return jsonify({
        'id': fav.id,
        'address': fav.address,
        'coordinates': fav.coordinates
    }), 201


@app.route('/api/favorites/<int:fav_id>', methods=['DELETE'])
@api_key_required
def api_delete_favorite(fav_id):
    if not request.headers.get('X-USER-ID'):
        return jsonify({'error': 'User ID required'}), 400

    user_id = int(request.headers.get('X-USER-ID'))
    fav = Favorite.query.get_or_404(fav_id)

    if fav.user_id != user_id:
        return jsonify({'error': 'Not authorized'}), 403

    db.session.delete(fav)
    db.session.commit()

    return jsonify({'message': 'Favorite deleted'}), 200


@app.route('/api/search', methods=['GET'])
@api_key_required
def api_search_address():
    query = request.args.get('q')
    if not query:
        return jsonify({'error': 'Search query required'}), 400

    try:
        geocode_url = "https://geocode-maps.yandex.ru/1.x/"
        params = {
            "apikey": app.config['YANDEX_MAPS_API_KEY'],
            "geocode": query,
            "format": "json",
            "results": 1
        }
        response = requests.get(geocode_url, params=params)
        response.raise_for_status()
        data = response.json()

        if not data["response"]["GeoObjectCollection"]["featureMember"]:
            return jsonify({'error': 'Address not found'}), 404

        feature = data["response"]["GeoObjectCollection"]["featureMember"][0]["GeoObject"]
        pos = feature["Point"]["pos"].split()
        lon, lat = pos[0], pos[1]

        address = feature["metaDataProperty"]["GeocoderMetaData"]["text"]
        postcode = feature["metaDataProperty"]["GeocoderMetaData"]["Address"].get("postal_code")

        return jsonify({
            'address': address,
            'postcode': postcode,
            'coordinates': f"{lon},{lat}",
            'map_url': generate_map_url(lon, lat,
                                        "country" in feature["metaDataProperty"]["GeocoderMetaData"].get("kind",
                                                                                                         "").lower())
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


def generate_map_url(lon, lat, is_country=False):
    zoom = "5" if is_country else "15"
    map_params = {
        "ll": f"{lon},{lat}",
        "z": zoom,
        "l": "map",
        "size": "650,450",
        "pt": f"{lon},{lat},pm2dgl"
    }
    return f"https://static-maps.yandex.ru/1.x/?{'&'.join(f'{k}={v}' for k, v in map_params.items())}"


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(username=form.username.data, password=hashed_pw)

            if form.avatar.data:
                avatar = form.avatar.data
                filename = secure_filename(f"user_{form.username.data}_{avatar.filename}")
                avatar_folder = os.path.join(app.root_path, 'static', 'avatars')

                os.makedirs(avatar_folder, exist_ok=True)

                avatar_path = os.path.join(avatar_folder, filename)
                logger.debug(f"Сохраняем аватар по пути: {avatar_path}")
                avatar.save(avatar_path)
                user.avatar = filename
            else:
                user.avatar = 'default.png'  # Устанавливаем аватар по умолчанию

            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash('Регистрация успешна!', 'success')
            return redirect(url_for('dashboard'))

        except Exception as e:
            db.session.rollback()
            logger.error(f"Ошибка при регистрации: {str(e)}", exc_info=True)
            flash('Произошла ошибка при регистрации', 'danger')

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(username=form.username.data).first()

            if not user:
                flash('Пользователь не найден', 'danger')
                app.logger.warning(f"Попытка входа несуществующего пользователя: {form.username.data}")
                return redirect(url_for('login'))

            if not bcrypt.check_password_hash(user.password, form.password.data):
                flash('Неверный пароль', 'danger')
                app.logger.warning(f"Неверный пароль для пользователя: {user.username}")
                return redirect(url_for('login'))

            login_user(user)
            app.logger.info(f"Успешный вход пользователя: {user.username}")
            return redirect(url_for('dashboard'))

        except Exception as e:
            app.logger.error(f"Ошибка входа: {str(e)}", exc_info=True)
            flash('Произошла ошибка при входе', 'danger')

    return render_template('login.html', form=form)


@app.route('/delete_favorite/<int:fav_id>', methods=['POST'])
@login_required
def delete_favorite(fav_id):
    fav = Favorite.query.get_or_404(fav_id)
    if fav.user_id != current_user.id:
        abort(403)
    db.session.delete(fav)
    db.session.commit()
    flash('Адрес удален из избранного', 'success')
    return redirect(url_for('dashboard'))


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = SearchForm()
    map_url = address = postcode = None
    show_postcode = False

    if 'last_search' in session:
        address = session['last_search'].get('address')
        postcode = session['last_search'].get('postcode')
        map_url = session['last_search'].get('map_url')
        show_postcode = session['last_search'].get('show_postcode', False)

    if form.reset.data:
        session.pop('last_search', None)
        return redirect(url_for('dashboard'))

    if form.submit.data and form.validate():
        try:
            geocode_url = "https://geocode-maps.yandex.ru/1.x/"
            params = {
                "apikey": app.config['YANDEX_MAPS_API_KEY'],
                "geocode": form.query.data,
                "format": "json",
                "results": 1
            }
            response = requests.get(geocode_url, params=params)
            response.raise_for_status()
            data = response.json()

            if not data["response"]["GeoObjectCollection"]["featureMember"]:
                flash('Адрес не найден', 'danger')
                return redirect(url_for('dashboard'))

            feature = data["response"]["GeoObjectCollection"]["featureMember"][0]["GeoObject"]
            pos = feature["Point"]["pos"].split()
            lon, lat = pos[0], pos[1]

            address = feature["metaDataProperty"]["GeocoderMetaData"]["text"]
            postcode = feature["metaDataProperty"]["GeocoderMetaData"]["Address"].get("postal_code")

            kind = feature["metaDataProperty"]["GeocoderMetaData"].get("kind", "")
            is_country = "country" in kind.lower()
            zoom = "5" if is_country else "15"

            map_url = generate_map_url(lon, lat, is_country)

            session['last_search'] = {
                'address': address,
                'postcode': postcode,
                'map_url': map_url,
                'show_postcode': form.show_postcode.data,
                'coordinates': f"{lon},{lat}"
            }

        except Exception as e:
            flash(f'Ошибка: {str(e)}', 'danger')

    if request.method == 'POST' and 'add_to_favorite' in request.form and 'last_search' in session:
        try:
            existing = Favorite.query.filter_by(
                user_id=current_user.id,
                coordinates=session['last_search']['coordinates']
            ).first()

            if not existing:
                fav = Favorite(
                    user_id=current_user.id,
                    address=session['last_search']['address'],
                    coordinates=session['last_search']['coordinates']
                )
                db.session.add(fav)
                db.session.commit()
                flash('Адрес добавлен в избранное', 'success')
            else:
                flash('Этот адрес уже в избранном', 'info')
        except Exception as e:
            flash(f'Ошибка при добавлении в избранное: {str(e)}', 'danger')

    return render_template(
        'dashboard.html',
        form=form,
        username=current_user.username,
        map_url=map_url,
        address=address,
        postcode=postcode,
        show_postcode=show_postcode,
        favorites=current_user.favorites
    )


@app.route('/favorite/<int:fav_id>')
@login_required
def show_favorite(fav_id):
    fav = Favorite.query.get_or_404(fav_id)
    if fav.user_id != current_user.id:
        abort(403)

    lon, lat = fav.coordinates.split(',')
    is_country = "страна" in fav.address.lower()
    zoom = "5" if is_country else "15"

    map_url = generate_map_url(lon, lat, is_country)

    session['last_search'] = {
        'address': fav.address,
        'map_url': map_url,
        'show_postcode': False,
        'coordinates': fav.coordinates
    }

    return redirect(url_for('dashboard'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    print(f"Сервер запущен. API_KEY: {app.config['API_KEY']}")
    app.run(port=8080, host='127.0.0.1')
