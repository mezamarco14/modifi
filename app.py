from flask import Flask, request, redirect, url_for, session, jsonify
from msal import ConfidentialClientApplication
from oauthlib.oauth2 import WebApplicationClient
import requests
import os
from dotenv import load_dotenv

# Cargar las variables de entorno
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')

# Configuración de Microsoft (Azure)
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
AUTHORITY = os.getenv('AUTHORITY')
REDIRECT_PATH = os.getenv('REDIRECT_PATH')
SCOPE = ["User.Read"]

# Configuración de Google OAuth
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_DISCOVERY_URL = os.getenv("GOOGLE_DISCOVERY_URL")

# Configuración del cliente MSAL para Azure (Microsoft)
app_msal = ConfidentialClientApplication(
    CLIENT_ID,
    authority=AUTHORITY,
    client_credential=CLIENT_SECRET,
)

# Configuración del cliente de Google OAuth
google_client = WebApplicationClient(GOOGLE_CLIENT_ID)

@app.route('/seleccion_proveedor')
def seleccion_proveedor():
    """
    Página donde el usuario selecciona el proveedor de autenticación (Microsoft o Google).
    """
    return """
    <html>
        <body>
            <h1>Selecciona el proveedor de autenticación</h1>
            <form action="/auth" method="post">
                <label for="proveedor">Proveedor:</label>
                <select name="proveedor" id="proveedor">
                    <option value="microsoft">Microsoft</option>
                    <option value="google">Google</option>
                </select>
                <button type="submit">Autenticarse</button>
            </form>
        </body>
    </html>
    """

@app.route('/auth', methods=['POST'])
def authenticate():
    """
    Redirige al cliente al proveedor de autenticación seleccionado.
    """
    proveedor = request.form.get("proveedor")
    
    if proveedor == 'microsoft':
        return redirect(microsoft_login())
    elif proveedor == 'google':
        return redirect(google_login())
    else:
        return jsonify({'error': 'Proveedor no soportado'}), 400

def microsoft_login():
    """
    Redirige al cliente de Microsoft para iniciar sesión y devolver el código de autorización.
    """
    auth_url = app_msal.get_authorization_request_url(
        SCOPE,
        redirect_uri=url_for("microsoft_authorized", _external=True)
    )
    return auth_url

@app.route(REDIRECT_PATH)
def microsoft_authorized():
    """
    Microsoft maneja la autorización y redirige a esta ruta.
    Aquí, intercambiamos el código por un token y obtenemos la información del usuario.
    """
    code = request.args.get('code')
    if not code:
        return "Error: No se obtuvo el código de autorización", 400

    result = app_msal.acquire_token_by_authorization_code(
        code,
        scopes=SCOPE,
        redirect_uri=url_for("microsoft_authorized", _external=True)
    )

    if "access_token" in result:
        user_info = result.get('id_token_claims')
        email = user_info.get("preferred_username")
        name = user_info.get("name")
        roles = user_info.get("roles", ["user"])

        # Redirigir a la ruta local con los datos
        return redirect(f"http://localhost:5000/usuario?email={email}&name={name}&roles={roles}")
    else:
        return "Error: No se obtuvo el token", 400


def google_login():
    """
    Redirige al cliente de Google para iniciar sesión y devolver el código de autorización.
    """
    google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    request_uri = google_client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=url_for("google_authorized", _external=True),
        scope=["openid", "email", "profile"],
    )
    return request_uri

@app.route('/google/authorized')
def google_authorized():
    """
    Google maneja la autorización y redirige a esta ruta.
    Aquí, intercambiamos el código por un token y obtenemos la información del usuario.
    """
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

        # Redirigir a la ruta local con los datos
        return redirect(f"http://localhost:5000/usuario?email={email}&name={name}&roles={roles}")
    else:
        return "Error: No se pudo verificar el correo electrónico de Google.", 400

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
