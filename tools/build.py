"""公開ページ（index.html）を作る。中身はすべて合言葉で暗号化する。

使い方:
  python3 tools/build.py --pass 合言葉 --csv out
      out/ の gp_month.csv・store_month.csv・daily_store.csv と、
      data/static.enc（画面の作り・事業計画・売上推移。暗号化済み）から index.html を作る。
  python3 tools/build.py --pass 合言葉 --init dashboard.html msp_plan.csv msp_history.csv
      data/static.enc を作り直す（画面の作りや計画データを差し替えるとき）。
"""
import argparse, base64, csv, datetime, json, os, secrets, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ITER = 250000


def key(pw, salt):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(pw.encode())


def seal(obj, pw):
    salt, iv = secrets.token_bytes(16), secrets.token_bytes(12)
    ct = AESGCM(key(pw, salt)).encrypt(iv, json.dumps(obj, ensure_ascii=False).encode(), None)
    b = lambda x: base64.b64encode(x).decode()
    return {'v': 1, 'iter': ITER, 'salt': b(salt), 'iv': b(iv), 'ct': b(ct)}


def unseal(box, pw):
    d = lambda x: base64.b64decode(x)
    return json.loads(AESGCM(key(pw, d(box['salt']))).decrypt(d(box['iv']), d(box['ct']), None))


def read(p):
    with open(p, encoding='utf-8') as f:
        return f.read().replace('\r\n', '\n')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pass', dest='pw', required=True)
    ap.add_argument('--csv')
    ap.add_argument('--init', nargs=3, metavar=('HTML', 'PLAN', 'HISTORY'))
    a = ap.parse_args()
    static_path = os.path.join(ROOT, 'data', 'static.enc')
    if a.init:
        html, plan, hist = a.init
        os.makedirs(os.path.dirname(static_path), exist_ok=True)
        with open(static_path, 'w') as f:
            json.dump(seal({'html': read(html), 'msp_plan': read(plan), 'msp_history': read(hist)}, a.pw), f)
        print('wrote', static_path)
        if not a.csv:
            return
    with open(static_path) as f:
        st = unseal(json.load(f), a.pw)
    data = {'msp_plan': st['msp_plan'], 'msp_history': st['msp_history']}
    for n in ['gp_month', 'store_month', 'daily_store']:
        data[n] = read(os.path.join(a.csv, n + '.csv'))
    rows = list(csv.DictReader(data['gp_month'].splitlines()))
    built = rows[0]['as_of'] if rows else datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
    payload = seal({'html': st['html'], 'data': data, 'built': built}, a.pw)
    shell = read(os.path.join(HERE, 'shell.html'))
    out = shell.replace('__PAYLOAD__', json.dumps(payload))
    with open(os.path.join(ROOT, 'index.html'), 'w', encoding='utf-8') as f:
        f.write(out)
    print('wrote index.html', len(out), 'bytes, built', built)


if __name__ == '__main__':
    main()
