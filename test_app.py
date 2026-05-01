#!/usr/bin/env python3
"""
Tests automatiques AlgoStudio Web
Exécutés par GitHub Actions à chaque push
"""
import sys, os, collections
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'core'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from server import app, _rate_limiter, _global_limiter, _ban_list

c   = app.test_client()
OK  = []
ERR = []

def reset():
    _rate_limiter._windows   = collections.defaultdict(list)
    _global_limiter._window  = []
    _ban_list._violations    = collections.defaultdict(list)
    _ban_list._bans          = {}

def T(name, fn):
    reset()
    try:
        ok, detail = fn()
        (OK if ok else ERR).append((name, detail))
        print(f'{"✅" if ok else "❌"} {name}: {detail}')
    except Exception as e:
        ERR.append((name, str(e)))
        print(f'💥 {name}: {e}')

def run(src, inputs=[]):
    r = c.post('/api/run', json={'source': src, 'inputs': inputs})
    return r.status_code, r.get_json() or {}

# ── Exécution ─────────────────────────────────────────────────
def t1():
    _, d = run('algorithme T;debut ecrire(42);fin.')
    return not d.get('error') and '42' in d.get('output',''), d.get('output','').strip()
T('Exécution simple', t1)

def t2():
    _, d = run('algorithme T;var a,b:entier;debut lire(a);lire(b);ecrire(a+b);fin.', ['10','32'])
    return not d.get('error') and '42' in d.get('output',''), d.get('output','').strip()
T('Lire() avec inputs', t2)

def t3():
    _, d = run('algorithme T;var i,s:entier;debut s:=0;pour i:=1 a 10 faire s:=s+i;fin;ecrire(s);fin.')
    return not d.get('error') and '55' in d.get('output',''), d.get('output','').strip()
T('Boucle Pour', t3)

def t4():
    _, d = run('Fonction f(E/ n:entier):entier\ndebut retourner n*2;fin;\nalgorithme T;debut ecrire(f(21));fin.')
    return not d.get('error') and '42' in d.get('output',''), d.get('output','').strip()
T('Fonction + Retourner', t4)

# ── Lire() interactif ─────────────────────────────────────────
def t5():
    _, d = run('algorithme T;var x:entier;debut lire(x);ecrire(x);fin.', [])
    return d.get('needs_input') == True, f'needs_input={d.get("needs_input")}'
T('Lire() sans input → needs_input', t5)

# ── Export ────────────────────────────────────────────────────
def t6():
    r = c.post('/api/generate', json={'source':'algorithme T;var x:entier;debut x:=42;ecrire(x);fin.','lang':'c'})
    d = r.get_json() or {}
    return not d.get('error') and '#include' in d.get('code',''), 'OK'
T('Export C', t6)

def t7():
    r = c.post('/api/generate', json={
        'source': 'Fonction f(E/ n:entier):entier\ndebut retourner n*2;fin;\nalgorithme T;debut ecrire(f(21));fin.',
        'lang': 'c'
    })
    d = r.get_json() or {}
    return not d.get('error') and 'int f(' in d.get('code',''), 'Fonction OK'
T('Export C avec Fonction', t7)

def t8():
    r = c.post('/api/generate', json={'source':'algorithme T;var x:entier;debut x:=42;ecrire(x);fin.','lang':'python'})
    d = r.get_json() or {}
    return not d.get('error') and 'def main' in d.get('code',''), 'OK'
T('Export Python', t8)

# ── Sécurité ──────────────────────────────────────────────────
def t9():
    _, d = run('algorithme T;var n:entier;debut n:=0;tantque vrai faire n:=n+1;fin;ecrire(n);fin.')
    return bool(d.get('error')), d.get('error','')[:50]
T('Boucle infinie bloquée', t9)

def t10():
    src = 'algorithme T;\nvar s:chaine;big:chaine;i:entier;\ndebut\nbig:="'+'a'*100+'";\ns:="";\npour i:=1 a 10000 faire s:=concat(s,big);fin;\necrire(long(s));\nfin.'
    _, d = run(src)
    return bool(d.get('error')) and 'longue' in d.get('error','').lower(), d.get('error','')[:50]
T('String bomb bloquée', t10)

def t11():
    _, d = run('algorithme T;var f:fichier;c:chaine;debut ouvrir(f,"/etc/passwd","lecture");lire(f,c);ecrire(c);fermer(f);fin.')
    return bool(d.get('error')) and 'désactivé' in d.get('error',''), d.get('error','')[:50]
T('File access bloqué', t11)

def t12():
    r = c.post('/api/run', json={'source': 'x'*200_000, 'inputs': []})
    return r.status_code == 413, f'HTTP {r.status_code}'
T('Source 200KB → 413', t12)

def t13():
    r = c.post('/api/run', content_type='text/plain', data='hello')
    return r.status_code == 415, f'HTTP {r.status_code}'
T('Content-Type invalide → 415', t13)

# ── Rate limit ────────────────────────────────────────────────
def t14():
    blocked = 0
    for _ in range(40):
        r = c.post('/api/run', json={'source':'algorithme T;debut ecrire(1);fin.','inputs':[]})
        if r.status_code == 429: blocked += 1
    return blocked >= 10, f'{blocked}/40 bloquées'
T('Rate limit 30/min', t14)

def t15():
    for _ in range(10): _ban_list.record_violation('9.9.9.9')
    r = c.post('/api/run', json={'source':'algorithme T;debut ecrire(1);fin.','inputs':[]},
               environ_base={'REMOTE_ADDR': '9.9.9.9'})
    return r.status_code == 429, f'HTTP {r.status_code}'
T('Ban automatique actif', t15)

# ── Save / Load ───────────────────────────────────────────────
def t16():
    reset()
    r1 = c.post('/api/save', json={'source':'algorithme T;debut ecrire(99);fin.','title':'Test'})
    d1 = r1.get_json() or {}
    sid = d1.get('id','')
    if not sid: return False, 'No ID returned'
    r2 = c.get(f'/api/load/{sid}')
    d2 = r2.get_json() or {}
    return d2.get('code') == 'algorithme T;debut ecrire(99);fin.', f'id={sid}'
T('Save + Load snippet', t16)

def t17():
    for bad in ['../server', 'ZZZZZZZZ', '<script>', 'abc']:
        r = c.get(f'/api/load/{bad}')
        if r.status_code not in (400, 404):
            return False, f'Bad ID {bad!r} → HTTP {r.status_code}'
    return True, 'Tous les bad IDs rejetés'
T('IDs invalides rejetés', t17)

# ── API misc ─────────────────────────────────────────────────
def t18():
    r = c.get('/api/health')
    d = r.get_json() or {}
    return r.status_code == 200 and d.get('status') == 'ok', 'OK'
T('Health endpoint', t18)

def t19():
    r = c.get('/api/examples')
    d = r.get_json() or {}
    total = sum(len(v) for v in d.values())
    return total >= 20, f'{total} exemples'
T('Exemples API', t19)

# ── Résultats ────────────────────────────────────────────────
print()
print(f'{"="*50}')
print(f'  RÉSULTATS : {len(OK)}/{len(OK)+len(ERR)} tests passés')
print(f'{"="*50}')

if ERR:
    print('\nÉCHECS:')
    for name, detail in ERR:
        print(f'  ❌ {name}: {detail}')
    sys.exit(1)
else:
    print('\n✅ Tous les tests passés — prêt pour le déploiement!')
    sys.exit(0)
