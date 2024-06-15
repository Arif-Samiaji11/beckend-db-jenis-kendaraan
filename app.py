from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from argon2 import PasswordHasher
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, JWTManager
from datetime import timedelta

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:@127.0.0.1/myflask1"
db = SQLAlchemy(app)

app.config["JWT_SECRET_KEY"] = "super-secret"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
jwt = JWTManager(app)

ph = PasswordHasher()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(200), nullable=False)


with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return 'Welcome to my Flask app!'


@app.post('/signup')
def signup():
    data = request.get_json()
    name = data["name"]
    email = data["email"]
    password = data["password"]

    if not email:
        return {"message": "Email harus diisi"}, 400

    hashed_password = ph.hash(password)
    new_user = User(email=email, name=name, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return {"message": "Successfully"}, 201


@app.post("/login")
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return {"message": "Email dan kata sandi diperlukan!"}, 400

    user = User.query.filter_by(email=email).first()

    if not user or not ph.verify(user.password, password):
        return {"message": "Email atau kata sandi salah!"}, 400

    access_token = create_access_token(identity=user.id)
    return {"token_access": access_token}, 200


@app.get("/myprofile")
@jwt_required()
def profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return {"message": "Pengguna tidak ditemukan."}, 404

    return {"id": user.id, "email": user.email, "name": user.name}, 200


@app.put("/updateprofile")
@jwt_required()
def update_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return {"message": "Pengguna tidak ditemukan."}, 404

    data = request.json
    new_name = data.get("name")
    new_email = data.get("email")

    if not new_name or not new_email:
        return {"message": "Nama dan email harus diisi."}, 400

    user.name = new_name
    user.email = new_email
    db.session.commit()

    return {"message": "Profil berhasil diperbarui."}, 200


@app.put("/changepassword")
@jwt_required()
def change_password():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return {"message": "Pengguna tidak ditemukan."}, 404

    data = request.json
    old_password = data.get("old_password")
    new_password = data.get("new_password")

    if not old_password or not new_password:
        return {"message": "Kata sandi lama dan baru harus diisi."}, 400

    # Verifikasi bahwa kata sandi lama sesuai
    if not ph.verify(user.password, old_password):
        return {"message": "Kata sandi lama salah."}, 400

    # Hash dan simpan kata sandi baru
    hashed_new_password = ph.hash(new_password)
    user.password = hashed_new_password
    db.session.commit()

    return {"message": "Kata sandi berhasil diperbarui."}, 200

if __name__ == "__main__":
    app.run(debug=True, host="192.168.1.10")
