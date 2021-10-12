import requests
import json



mc_auth_url0 = r'https://login.live.com/oauth20_authorize.srf'
mc_auth_url1 = r'?client_id=000000004C12AE6F'
mc_auth_url2 = r'&redirect_uri=https://login.live.com/oauth20_desktop.srf'
mc_auth_url3 = r'&scope=service::user.auth.xboxlive.com::MBI_SSL'
mc_auth_url4 = r'&display=touch&response_type=token&locale=en'

MICROSOFT_AUTH_URL = mc_auth_url0 + mc_auth_url1 + mc_auth_url2 + mc_auth_url3 + mc_auth_url4

AUTH_TOKEN_URL = r'https://login.live.com/oauth20_token.srf'

XBL_URL = r'https://user.auth.xboxlive.com/user/authenticate'
XSTS_URL = r'https://xsts.auth.xboxlive.com/xsts/authorize'

MC_URL = r'https://api.minecraftservices.com'
MC_SESSION_URL = r'https://sessionserver.mojang.com/session/minecraft/join'

login_xbox_url = r'/authentication/login_with_xbox'
mcstore_url = r'/entitlements/mcstore'
mc_profile = r'/minecraft/profile'

def login_to_microsoft():

    print(MICROSOFT_AUTH_URL)

    login_request = input('- Paste the Generated URL here : ')

    raw_login_data = login_request.split("#")[1] # split the url to get the parameters
    login_data = dict(item.split("=") for item in raw_login_data.split("&")) # create a dictionary of the parameters
    login_data["access_token"] = requests.utils.unquote(login_data["access_token"]) # URL decode the access token
    login_data["refresh_token"] = requests.utils.unquote(login_data["refresh_token"]) # URL decode the refresh token

    return login_data

def get_XBL_token(microsoft_access_token):

    parameters = {
        "Properties": {
            "AuthMethod": "RPS",
            "SiteName": "user.auth.xboxlive.com",
            "RpsTicket": microsoft_access_token
        },
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT"
    }

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    responce = requests.post(XBL_URL, json = parameters , headers = headers)
    xbl_responce = json.loads(responce.text)

    xbl_token = xbl_responce['Token']
    xbl_user_hash = xbl_responce['DisplayClaims']['xui'][0]['uhs']

    return xbl_token , xbl_user_hash

def get_XSTS_token(xbl_token):

    parameters = {
        "Properties": {
            "SandboxId": "RETAIL",
            "UserTokens": [
                xbl_token
            ]
        },
        "RelyingParty": "rp://api.minecraftservices.com/",
        "TokenType": "JWT"
    }

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    responce = requests.post( XSTS_URL, json=parameters, headers=headers)
    return json.loads(responce.text)['Token']

def get_minecraft_token(xsts_token, xbl_user_hash):

    parameters = {
        "identityToken" : f"XBL3.0 x={xbl_user_hash};{xsts_token}"
    }

    headers = {
        "Content-Type": "application/json"
    }

    responce = requests.post(MC_URL+login_xbox_url , json=parameters, headers=headers)
    return json.loads(responce.text)['access_token']

def check_game_ownership(minecraft_token):

    headers = {
        'Authorization' : f'Bearer {minecraft_token}'
    }

    responce = requests.get(MC_URL + mcstore_url, headers = headers)
    return json.loads(responce.text)

def get_minecraft_profile(minecraft_token):

    headers = {
        'Authorization' : f'Bearer {minecraft_token}'
    }

    responce = requests.get(MC_URL + mc_profile, headers = headers)
    output = json.loads(responce.text)
    return output['id'], output['name']

def join_server(minecraft_token, uuid, server_hash):

    parameters = {
        "accessToken": f"{minecraft_token}",
        "selectedProfile": f"{uuid}",
        "serverId": f"{server_hash}"
    }

    headers = {
        "Content-Type": "application/json"
    }

    responce = requests.post(MC_SESSION_URL, json = parameters , headers = headers)
    return responce

def login_through_microsoft():

    login_data = login_to_microsoft()
    xbl_token, xbl_user_hash = get_XBL_token(login_data["access_token"])
    xsts_token = get_XSTS_token(xbl_token)
    access_token = get_minecraft_token(xsts_token, xbl_user_hash)
    uuid , name = get_minecraft_profile(access_token)

    return uuid, name, access_token, login_data

# uuid , name , token , login_data = login_through_microsoft()
#
# print(uuid)
# print(name)
# print(login_data)
















# f
