from flask import Flask, request, jsonify, redirect, url_for
from msal import ConfidentialClientApplication
from oauthlib.oauth2 import WebApplicationClient
import requests
import jwt
import os
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

app = Flask(__name__)

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
    client_credential=CLIENT_SECRET
)

# Configuración del cliente de Google OAuth
google_client = WebApplicationClient(GOOGLE_CLIENT_ID)


@app.route('/auth/<provider>', methods=['POST'])
def authenticate(provider):
    """
    El cliente de la VPS hace una solicitud al intermediario para elegir el proveedor de autenticación
    (Microsoft o Google) para obtener la información del usuario.
    """
    if provider == 'microsoft':
        return redirect(microsoft_login())
    elif provider == 'google':
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

        # Enviar los datos de usuario al API en la VPS
        return jsonify({"email": email, "name": name, "roles": roles})
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

        # Enviar los datos de usuario al API en la VPS
        return jsonify({"email": email, "name": name, "roles": roles})
    else:
        return "Error: No se pudo verificar el correo electrónico de Google.", 400


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
