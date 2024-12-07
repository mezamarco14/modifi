import requests
from flask import Flask, redirect, request, jsonify, session, url_for
from msal import ConfidentialClientApplication
from oauthlib.oauth2 import WebApplicationClient
import os
from user_agents import parse  # Instalar con `pip install pyyaml user-agents`
from pymongo import MongoClient
import certifi

# Inicializar la aplicación Flask
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "default_secret_key")

# Conexión a MongoDB Atlas
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(
    MONGO_URI,
    tls=True,
    tlsCAFile=certifi.where()
)
db = client['db_Upt_Usuarios']
accesos_users_collection = db['Accesos_users']

# Variables de entorno para Microsoft (Azure)
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
AUTHORITY = os.getenv("AUTHORITY")
REDIRECT_PATH = os.getenv("REDIRECT_PATH")
SCOPE = ["User.Read"]

# Variables de entorno para Google
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_DISCOVERY_URL = os.getenv("GOOGLE_DISCOVERY_URL")
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Solo para desarrollo

# Configuración de MSAL y Google OAuth
app_msal = ConfidentialClientApplication(
    CLIENT_ID,
    authority=AUTHORITY,
    client_credential=CLIENT_SECRET,
)

google_client = WebApplicationClient(GOOGLE_CLIENT_ID)

# Ruta de inicio de sesión
@app.route('/')
def index():
    # Verificar si el usuario está autenticado
    if session.get("user"):
        # Detectar dispositivo móvil
        user_agent = request.headers.get("User-Agent")
        ua = parse(user_agent)
        if ua.is_mobile:
            # Si es móvil, mostrar los datos en la interfaz
            return f"Hola, {session['user']['name']}! Roles: {session.get('roles', [])}"
        else:
            # Si es web, redirigir a la IP final
            email = session['user']['email']
            name = session['user']['name']
            roles = session.get('roles', [])
            return redirect(f"http://161.132.50.153/?email={email}&name={name}&roles={','.join(roles)}")
    else:
        return '''
            <h1>Bienvenido</h1>
            <p>Inicia sesión con:</p>
            <a href="/login">Microsoft</a><br>
            <a href="/google/login">Google</a>
        '''

# Ruta para iniciar sesión con Microsoft
@app.route('/login')
def login():
    auth_url = app_msal.get_authorization_request_url(
        SCOPE,
        redirect_uri=url_for("authorized", _external=True)
    )
    return redirect(auth_url)

# Ruta de callback de Microsoft
@app.route(REDIRECT_PATH)
def authorized():
    code = request.args.get('code')
    if not code:
        return "Error al obtener el código de autorización", 400

    result = app_msal.acquire_token_by_authorization_code(
        code,
        scopes=SCOPE,
        redirect_uri=url_for("authorized", _external=True)
    )

    if "access_token" in result:
        user_info = result.get('id_token_claims')
        email = user_info.get("preferred_username")  # Email
        name = user_info.get("name")  # Nombre
        roles = result.get('id_token_claims', {}).get('roles', [])

        if not roles:
            roles = ["user"]

        # Guardar en la sesión
        session['user'] = {'email': email, 'name': name}
        session['roles'] = roles

        # Guardar en la base de datos
        user_data = {
            "email": email,
            "name": name,
            "roles": roles
        }
        accesos_users_collection.insert_one(user_data)

        return redirect("/")  # Redirigir al índice

    return "Error al obtener el token de acceso", 400

# Ruta de login de Google
@app.route('/google/login')
def google_login():
    google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    request_uri = google_client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=url_for("google_authorized", _external=True),
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)

# Ruta de callback de Google
@app.route('/google/authorized')
def google_authorized():
    code = request.args.get("code")
    google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
    token_endpoint = google_provider_cfg["token_endpoint"]

    token_url, headers, body = google_client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=url_for("google_authorized", _external=True),
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    google_client.parse_request_body_response(token_response.text)

    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = google_client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    if userinfo_response.json().get("email_verified"):
        email = userinfo_response.json()["email"]
        name = userinfo_response.json()["name"]
        roles = ["user"]

        # Guardar en la sesión
        session['user'] = {'email': email, 'name': name}
        session['roles'] = roles

        # Guardar en la base de datos
        user_data = {
            "email": email,
            "name": name,
            "roles": roles
        }
        accesos_users_collection.insert_one(user_data)

        return redirect("/")  # Redirigir al índice

    return "Error: No se pudo verificar el correo electrónico de Google.", 400

# Ruta de logout
@app.route('/logout')
def logout():
    # Limpiar los datos de la sesión
    session.pop('user', None)
    session.pop('roles', None)

    # Redirigir al inicio después de cerrar sesión
    return redirect("/")

# Arrancar la aplicación Flask en el puerto 5000
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
