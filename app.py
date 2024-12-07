import requests
import jwt
import datetime
from flask import Flask, redirect, request, url_for, session
from msal import ConfidentialClientApplication
from oauthlib.oauth2 import WebApplicationClient
import os

# Inicializar la aplicación Flask
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "default_secret_key")

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

        # Si el correo no tiene rol de admin, asignamos el rol de user por defecto
        if not roles:
            roles = ["user"]
        elif "admin" not in roles:
            roles.append("user")

        # Crear el JWT con los datos del usuario
        token = create_jwt(email, name, roles)

        # Si la solicitud proviene de un dispositivo móvil, mostrar los datos directamente
        if is_mobile(request.headers.get('User-Agent', '')):
            return f"Hola, {name}! Roles: {', '.join(roles)}"

        # Si no es móvil, redirigir a la IP final con el JWT
        redirect_url = f"http://161.132.50.153/?token={token}"
        return redirect(redirect_url)

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

        # Si el correo no tiene rol de admin, asignamos el rol de user por defecto
        if "admin" not in roles:
            roles.append("user")

        # Crear el JWT con los datos del usuario
        token = create_jwt(email, name, roles)

        # Si la solicitud proviene de un dispositivo móvil, mostrar los datos directamente
        if is_mobile(request.headers.get('User-Agent', '')):
            return f"Hola, {name}! Roles: {', '.join(roles)}"

        # Si no es móvil, redirigir a la IP final con el JWT
        redirect_url = f"http://161.132.50.153/?token={token}"
        return redirect(redirect_url)

    return "Error: No se pudo verificar el correo electrónico de Google.", 400

# Función para crear el JWT
def create_jwt(email, name, roles):
    payload = {
        'sub': email,
        'name': name,
        'roles': roles,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    secret_key = os.getenv("JWT_SECRET_KEY", "default_secret_key")
    token = jwt.encode(payload, secret_key, algorithm="HS256")
    return token

# Función para determinar si la solicitud proviene de un dispositivo móvil
def is_mobile(user_agent):
    mobile_keywords = ["iphone", "android", "blackberry", "windows phone", "mobile"]
    user_agent = user_agent.lower()
    return any(keyword in user_agent for keyword in mobile_keywords)

# Ruta para cerrar sesión (Logout)
@app.route('/logout')
def logout():
    # Limpiar la sesión de Flask
    session.clear()

    # Si el usuario estaba conectado a través de Google o Microsoft, puedes hacer un logout desde el proveedor
    # Redirigir a la página de inicio después de hacer logout
    return redirect(url_for('index'))

# Arrancar la aplicación Flask en el puerto 5000
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
