import re
import json
import argparse
import subprocess
import urllib.request
import uuid
from pathlib import Path

BASE_DIR = Path(__file__).parent
CONFIG_PATH = BASE_DIR / "xray_server.json"
KEYCHAIN_PATH = BASE_DIR / "keychain.json"
XRAY_BINARY_PATH = BASE_DIR / "xray"


def get_ip() -> str:
    request = urllib.request.urlopen("https://ipinfo.io/json")
    data = json.loads(request.read().decode("utf-8"))
    return data["ip"]


def generate_vless_url(client: dict, pubkey: str, sid: str) -> str:
    return "vless://{}@{}:443?type=tcp&security=reality&pbk={}&fp=chrome&sni=google.com&sid={}&spx=%2F&flow=xtls-rprx-vision#{}".format(
        client["id"], get_ip(), pubkey, sid, client["email"]
    )


def generate_sid() -> str:
    sid = str(uuid.uuid4())
    return sid[0 : sid.find("-")]


def generate_keychain(private_key: str) -> dict:
    if not private_key:
        process = subprocess.Popen([XRAY_BINARY_PATH, "x25519"], stdout=subprocess.PIPE)
    else:
        process = subprocess.Popen(
            [XRAY_BINARY_PATH, "x25519", "-i", private_key],
            stdout=subprocess.PIPE,
        )
    result = process.stdout.read().decode("utf-8").strip()
    keys = re.findall(r": (.+?)$", result, re.M)
    return dict(zip(("private", "public"), keys))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--clients", action="store_true")
    parser.add_argument("--add-client", type=str, required=False)
    parser.add_argument("--remove-client", type=str, required=False)
    parser.add_argument("--get-url", type=str, required=False)
    parser.add_argument("--keychain", action="store_true")
    args = parser.parse_args()

    with open(CONFIG_PATH, "r", encoding="utf-8") as file:
        config = json.load(file)

    clients = config["inbounds"][1]["settings"]["clients"]
    streamSettings = config["inbounds"][1]["streamSettings"]
    private_key = streamSettings["realitySettings"]["privateKey"]

    keychain = generate_keychain(private_key)

    if args.clients:
        print("Clients ({}):".format(len(clients)))
        for idx, client in enumerate(clients):
            print("[{}] {}: {}".format(idx + 1, client["email"], client["id"]))
        return

    if args.add_client:
        email = args.add_client
        client = {
            "email": email,
            "enable": True,
            "expiryTime": 0,
            "flow": "xtls-rprx-vision",
            "id": "{}".format(str(uuid.uuid4())),
            "limitIp": 0,
            "reset": 0,
        }
        clients.append(client)
        config["inbounds"][1]["settings"]["clients"] = clients
        with open(CONFIG_PATH, "w", encoding="utf-8") as file:
            json.dump(config, file, indent=4)
        print("Client added: {} ({})".format(email, client["id"]))
        return

    if args.remove_client:
        email = args.remove_client
        for idx, client in enumerate(clients):
            if client["email"] == email:
                clients.pop(idx)
                config["inbounds"][1]["settings"]["clients"] = clients
                with open(CONFIG_PATH, "w", encoding="utf-8") as file:
                    json.dump(config, file, indent=4)
                print("Client removed: {}".format(email))
                return
        print("Client not found: {}".format(email))
        return

    if args.get_url:
        email = args.get_url
        for client in clients:
            if client["email"] == email:
                url = generate_vless_url(
                    client,
                    keychain["public"],
                    streamSettings["realitySettings"]["shortIds"][0],
                )
                print("{}: {}".format(email, client["id"]))
                print(url)
                return
        print("Client not found: {}".format(email))
        return

    if args.keychain:
        print(
            "Public key: {}\nPrivate key: {}".format(
                keychain["public"], keychain["private"]
            )
        )
        return


if __name__ == "__main__":
    main()
