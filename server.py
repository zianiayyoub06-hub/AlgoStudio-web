# -*- coding: utf-8 -*-
"""
AlgoStudio Web — Serveur Flask durci
Protections : rate-limit par IP réelle, sémaphore concurrence,
              limite mémoire strings, parser recursion, headers HTTP.
"""

import sys, os, threading, time, re

# 'resource' est Linux/Mac uniquement — ignoré sur Windows
try:
    import resource
except ImportError:
    resource = None
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'core'))

from flask import Flask, request, jsonify, send_from_directory, abort

from lexer import tokenize, LexerError

class _NeedsInputSignal(Exception):
    """Signal interne : Lire() a besoin d'une entrée supplémentaire."""
    def __init__(self, idx): self.idx = idx
from parser import Parser
from interpreter import Interpreter, AlgoRTError
from codegen import CodeGenC, CodeGenPython as CodeGenPy
from examples import EXAMPLES

app = Flask(__name__, static_folder='static')

# En production derrière un reverse proxy (Nginx, Railway, Render…)
# on fait confiance au header X-Forwarded-Proto pour savoir si la requête est HTTPS
# mais PAS à X-Forwarded-For pour le rate limiting (géré par Nginx)
if os.environ.get('PRODUCTION'):
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=0, x_proto=1, x_host=1)

# ══════════════════════════════════════════════════════════════
#  LIMITES
# ══════════════════════════════════════════════════════════════
MAX_SOURCE_BYTES      = 64_000    # 64 KB code source
MAX_INPUT_COUNT       = 50        # inputs par requête
MAX_INPUT_BYTES       = 512       # octets par input
MAX_OUTPUT_LINES      = 2_000     # lignes de sortie
MAX_REQUEST_BYTES     = 200_000   # taille totale requête
MAX_STRING_LEN        = 100_000   # longueur max d'une chaîne algo
EXEC_TIMEOUT_SEC      = 10        # timeout exécution
MAX_CONCURRENT        = 4         # exécutions simultanées max

# ══════════════════════════════════════════════════════════════
#  ANTI-DDOS — 3 couches de protection
# ══════════════════════════════════════════════════════════════
import collections

# ── Couche 1 : Rate limit par IP (30 req/min) ─────────────────
class _RateLimiter:
    """Token-bucket 60s fenêtre glissante par IP réelle."""
    def __init__(self, per_minute: int = 30):
        self._per_min = per_minute
        self._windows: dict = collections.defaultdict(list)
        self._lock = threading.Lock()

    def is_allowed(self, ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            wins = [t for t in self._windows[ip] if now - t < 60]
            self._windows[ip] = wins
            if len(wins) >= self._per_min:
                return False
            self._windows[ip].append(now)
            return True

_rate_limiter = _RateLimiter(per_minute=30)

# ── Couche 2 : Rate limit GLOBAL (200 req/min toutes IPs) ─────
class _GlobalLimiter:
    """Limite globale — protège contre DDoS distribué (IPs multiples)."""
    def __init__(self, per_minute: int = 200):
        self._per_min = per_minute
        self._window: list = []
        self._lock = threading.Lock()

    def is_allowed(self) -> bool:
        now = time.monotonic()
        with self._lock:
            self._window = [t for t in self._window if now - t < 60]
            if len(self._window) >= self._per_min:
                return False
            self._window.append(now)
            return True

_global_limiter = _GlobalLimiter(per_minute=200)

# ── Couche 3 : Bannissement temporaire des IPs agressives ─────
class _BanList:
    """
    Ban automatique : si une IP dépasse 10 violations en 5 min
    elle est bannie 15 minutes.
    """
    def __init__(self):
        self._violations: dict = collections.defaultdict(list)  # ip → [timestamps]
        self._bans: dict = {}                                    # ip → ban_until
        self._lock = threading.Lock()

    def record_violation(self, ip: str):
        now = time.monotonic()
        with self._lock:
            # Purge violations > 5 min
            self._violations[ip] = [
                t for t in self._violations[ip] if now - t < 300
            ]
            self._violations[ip].append(now)
            # 10 violations en 5 min → ban 15 min
            if len(self._violations[ip]) >= 10:
                self._bans[ip] = now + 900   # 900s = 15 min
                self._violations[ip] = []
                _log('WARN', f'IP bannie 15min: {ip}')

    def is_banned(self, ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            until = self._bans.get(ip)
            if until and now < until:
                return True
            if until:
                del self._bans[ip]   # ban expiré
            return False

    def ban_count(self) -> int:
        now = time.monotonic()
        with self._lock:
            return sum(1 for u in self._bans.values() if now < u)

_ban_list = _BanList()

# ══════════════════════════════════════════════════════════════
#  SÉMAPHORE — limite les exécutions simultanées
# ══════════════════════════════════════════════════════════════
_exec_semaphore = threading.Semaphore(MAX_CONCURRENT)

# ══════════════════════════════════════════════════════════════
#  HEADERS DE SÉCURITÉ
# ══════════════════════════════════════════════════════════════
@app.after_request
def _security_headers(resp):
    resp.headers['X-Frame-Options']           = 'DENY'
    resp.headers['X-Content-Type-Options']    = 'nosniff'
    resp.headers['X-XSS-Protection']          = '1; mode=block'
    resp.headers['Referrer-Policy']           = 'no-referrer'
    resp.headers['Content-Security-Policy']   = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com https://fonts.gstatic.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none';"
    )
    # Empêche la mise en cache de réponses sensibles
    if request.path.startswith('/api/'):
        resp.headers['Cache-Control'] = 'no-store'
    return resp

# ══════════════════════════════════════════════════════════════
#  HELPERS VALIDATION
# ══════════════════════════════════════════════════════════════
def _real_ip() -> str:
    """IP TCP directe — ne fait JAMAIS confiance aux headers X-Forwarded-For."""
    return request.remote_addr or '0.0.0.0'

def _check_request():
    """
    3 couches anti-DDoS :
    1. Taille + Content-Type
    2. Ban list (IPs agressives bannies 15min)
    3. Rate limit par IP (30/min)
    4. Rate limit global (200/min toutes IPs)
    """
    # ── Taille max ────────────────────────────────────────────
    if request.content_length and request.content_length > MAX_REQUEST_BYTES:
        abort(413)

    # ── Content-Type ──────────────────────────────────────────
    if not request.is_json:
        abort(415)

    ip = _real_ip()

    # ── Couche 3 : IP bannie ? ────────────────────────────────
    if _ban_list.is_banned(ip):
        time.sleep(0.5)   # slow-down pour ralentir le flood
        return jsonify({'error': 'IP temporairement bloquée. Réessayez dans 15 min.',
                        'output': '', 'variables': {}}), 429

    # ── Couche 1 : Rate limit par IP ─────────────────────────
    if not _rate_limiter.is_allowed(ip):
        _ban_list.record_violation(ip)   # compte la violation
        with _stats_lock:
            _stats['rate_limited'] += 1
        return jsonify({'error': 'Trop de requêtes (max 30/min). Patientez.',
                        'output': '', 'variables': {}}), 429

    # ── Couche 2 : Rate limit global (anti-DDoS distribué) ───
    if not _global_limiter.is_allowed():
        _ban_list.record_violation(ip)
        with _stats_lock:
            _stats['rate_limited'] += 1
        return jsonify({'error': 'Serveur surchargé. Réessayez dans quelques secondes.',
                        'output': '', 'variables': {}}), 429

    return None

def _clean_source(raw) -> tuple:
    """Valide et nettoie le code source."""
    if not isinstance(raw, str):
        return None, 'Le code source doit être une chaîne.'
    if len(raw.encode('utf-8', errors='replace')) > MAX_SOURCE_BYTES:
        return None, f'Code source trop long (max {MAX_SOURCE_BYTES // 1000} KB).'
    # Supprime caractères de contrôle, bytes nuls, surrogates
    cleaned = raw.encode('utf-8', errors='replace').decode('utf-8', errors='replace')
    cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x80-\x9f]', '', cleaned)
    return cleaned, None

def _clean_inputs(raw) -> tuple:
    """Valide la liste d'entrées utilisateur."""
    if not isinstance(raw, list):
        return None, 'Les entrées doivent être une liste.'
    if len(raw) > MAX_INPUT_COUNT:
        return None, f'Trop d\'entrées (max {MAX_INPUT_COUNT}).'
    result = []
    for item in raw:
        s = str(item)
        if len(s.encode('utf-8', errors='replace')) > MAX_INPUT_BYTES:
            return None, f'Valeur d\'entrée trop longue (max {MAX_INPUT_BYTES} octets).'
        result.append(s)
    return result, None

def _serialize(v):
    """Sérialise une valeur algo en string affichable, avec profondeur limitée."""
    def _inner(v, depth=0):
        if depth > 5: return '...'
        if v is None:          return 'NIL'
        if v is True:          return 'Vrai'
        if v is False:         return 'Faux'
        if isinstance(v, list):
            return '[' + ', '.join(_inner(x, depth+1) for x in v[:100]) + ']'
        if isinstance(v, dict):
            return '{' + ', '.join(f'{k}: {_inner(vv, depth+1)}' for k, vv in list(v.items())[:30]) + '}'
        if isinstance(v, float) and v == int(v):
            return str(int(v))
        return str(v)[:500]   # tronque les très longues valeurs
    return _inner(v)

# ══════════════════════════════════════════════════════════════
#  WRAPPER D'EXÉCUTION SÉCURISÉ
# ══════════════════════════════════════════════════════════════
class _SafeContext:
    """
    Injecte des checks de sécurité dans les callbacks de l'interpréteur.
    Limite la taille des chaînes créées pendant l'exécution.
    """
    def __init__(self, inputs):
        self.output_lines = []
        self.variables    = {}
        self.error        = None
        self._inputs      = inputs
        self._input_idx   = 0
        self._total_output_chars = 0
        self.needs_input = False
        self.needed_input_idx = 0
        self.MAX_TOTAL_CHARS = 500_000   # 500 KB de sortie max

    def output_cb(self, text):
        s = str(text)
        self._total_output_chars += len(s)
        if self._total_output_chars > self.MAX_TOTAL_CHARS:
            raise AlgoRTError('Limite de sortie atteinte (500 KB).')
        self.output_lines.append(s)
        if len(self.output_lines) > MAX_OUTPUT_LINES:
            raise AlgoRTError(f'Limite de sortie atteinte ({MAX_OUTPUT_LINES} lignes).')

    def input_cb(self):
        if self._input_idx < len(self._inputs):
            val = self._inputs[self._input_idx]
            self._input_idx += 1
            self.output_lines.append(f'→ {val}')
            return val
        # Pas d'input disponible → signaler au frontend qu'on en a besoin
        self.needs_input = True
        raise _NeedsInputSignal(self._input_idx)

    def step_cb(self, line, env):
        try:
            if env:
                snap = env.snapshot()
                self.variables = {
                    k: _serialize(v)
                    for k, v in snap.items()
                    if not k.startswith('_')
                }
        except Exception:
            pass


def _run_safe(source: str, inputs: list) -> dict:
    """Exécute le code algo dans un thread surveillé avec sémaphore."""
    # Semaphore : refuse si trop de threads actifs
    if not _exec_semaphore.acquire(blocking=False):
        return {'output': '', 'variables': {}, 'error': 'Serveur occupé. Réessayez dans quelques secondes.'}

    ctx  = _SafeContext(inputs)
    interp = None

    try:
        # Parsing (peut lever RecursionError sur source très imbriquée)
        try:
            tokens = tokenize(source)
            ast    = Parser(tokens).parse()
        except RecursionError:
            return {'output': '', 'variables': {}, 'error': 'Code trop imbriqué (limite de profondeur dépassée).'}
        except LexerError as e:
            return {'output': '', 'variables': {}, 'error': f'Erreur lexicale ligne {e.line}, col {e.col}: {e}'}
        except SyntaxError as e:
            return {'output': '', 'variables': {}, 'error': f'Erreur syntaxique: {e}'}
        except Exception as e:
            return {'output': '', 'variables': {}, 'error': f'Erreur de parsing: {e}'}

        # ── Bloquer les opérations fichier (dangereux côté serveur) ──
        import types as _t2
        _orig_call2 = Interpreter._call

        def _no_file_call(self_i, name, arg_nodes, env, line):
            if name.lower() in ('ouvrir', 'fermer', 'pointer', 'finfichier'):
                raise AlgoRTError(
                    f"'{name}()' est désactivé en version Web "
                    f"(opérations fichier non autorisées).", line)
            return _orig_call2(self_i, name, arg_nodes, env, line)

        interp = Interpreter(
            output_cb=ctx.output_cb,
            input_cb=ctx.input_cb,
            step_cb=ctx.step_cb,
        )
        interp._call = _t2.MethodType(_no_file_call, interp)

        # Patch _lval_set: limite la taille de toute chaine assignee
        import types as _types
        _orig_lval = interp._lval_set.__func__

        def _patched_lval(self_i, target, val, env):
            if isinstance(val, str) and len(val) > MAX_STRING_LEN:
                raise AlgoRTError(
                    f'Chaine trop longue ({len(val):,} car., max {MAX_STRING_LEN:,}).'
                )
            return _orig_lval(self_i, target, val, env)

        interp._lval_set = _types.MethodType(_patched_lval, interp)

        # Patch _call: intercepte les resultats de concat/chaine() etc.
        _orig_call = interp._call.__func__

        def _patched_call(self_i, name, arg_nodes, env, line):
            result = _orig_call(self_i, name, arg_nodes, env, line)
            if isinstance(result, str) and len(result) > MAX_STRING_LEN:
                raise AlgoRTError(
                    f'Chaine trop longue ({len(result):,} car., max {MAX_STRING_LEN:,}).'
                )
            return result

        interp._call = _types.MethodType(_patched_call, interp)

        done = threading.Event()
        exc  = [None]

        def _worker():
            try:
                interp.run(ast)
            except _NeedsInputSignal as e:
                ctx.needs_input = True
                ctx.needed_input_idx = e.idx
            except RecursionError:
                exc[0] = AlgoRTError('Débordement de pile (récursion trop profonde).')
            except MemoryError:
                exc[0] = AlgoRTError('Mémoire insuffisante (allocation trop grande).')
            except (AlgoRTError, Exception) as e:
                exc[0] = e
            finally:
                done.set()

        t = threading.Thread(target=_worker, daemon=True)
        t.start()

        if not done.wait(EXEC_TIMEOUT_SEC):
            if interp: interp.stop()
            return {
                'output':    '\n'.join(ctx.output_lines),
                'variables': ctx.variables,
                'error':     f'Timeout : exécution dépassant {EXEC_TIMEOUT_SEC}s.',
            }

        if exc[0]:
            e = exc[0]
            ctx.error = f'Erreur ligne {e.line}: {e}' if getattr(e, 'line', None) else str(e)

    except Exception as e:
        ctx.error = f'Erreur interne: {e}'
    finally:
        _exec_semaphore.release()

    return {
        'output':      '\n'.join(ctx.output_lines),
        'variables':   ctx.variables,
        'error':       ctx.error,
        'needs_input': ctx.needs_input,
        'input_idx':   ctx.needed_input_idx,
    }

# ══════════════════════════════════════════════════════════════
#  ROUTES API
# ══════════════════════════════════════════════════════════════
@app.route('/api/run', methods=['POST'])
def api_run():
    err_resp = _check_request()
    if err_resp: return err_resp

    data = request.get_json(silent=True) or {}

    source, err = _clean_source(data.get('source', ''))
    if err: return jsonify({'output': '', 'variables': {}, 'error': err})

    inputs, err = _clean_inputs(data.get('inputs', []))
    if err: return jsonify({'output': '', 'variables': {}, 'error': err})

    t0_exec = time.time()
    result  = _run_safe(source, inputs)
    elapsed = (time.time() - t0_exec) * 1000
    timeout = bool(result.get('error') and 'Timeout' in (result.get('error') or ''))
    _record_run(elapsed, result.get('error'), timeout)
    if result.get('error'):
        # Ne pas loguer les erreurs "attendues" (fichiers désactivés, Lire sans input)
        err = result['error']
        is_expected = any(x in err for x in [
            "désactivé en version Web",
            "aucune entrée fournie",
        ])
        if not is_expected:
            _log('WARN', f"run_error ip={_real_ip()} err={err[:80]}")
    return jsonify(result)


@app.route('/api/generate', methods=['POST'])
def api_generate():
    err_resp = _check_request()
    if err_resp: return err_resp

    data = request.get_json(silent=True) or {}

    source, err = _clean_source(data.get('source', ''))
    if err: return jsonify({'code': '', 'ext': '', 'error': err})

    lang = str(data.get('lang', 'python')).lower()
    if lang not in ('c', 'python'):
        return jsonify({'code': '', 'ext': '', 'error': 'Langue invalide (c ou python).'})

    try:
        tokens = tokenize(source)
        ast    = Parser(tokens).parse()
        if lang == 'c':
            code, ext = CodeGenC().generate(ast), 'c'
        else:
            code, ext = CodeGenPy().generate(ast), 'py'
        return jsonify({'code': code, 'ext': ext, 'error': None})
    except RecursionError:
        return jsonify({'code': '', 'ext': '', 'error': 'Code trop imbriqué.'})
    except LexerError as e:
        return jsonify({'code': '', 'ext': '', 'error': f'Erreur lexicale ligne {e.line}: {e}'})
    except Exception as e:
        return jsonify({'code': '', 'ext': '', 'error': str(e)})


@app.route('/api/examples', methods=['GET'])
def api_examples():
    result = {}
    for title, code in EXAMPLES.items():
        parts = title.split(' — ', 1)
        chap  = parts[0].strip() if len(parts) > 1 else 'Divers'
        name  = parts[1].strip() if len(parts) > 1 else title
        result.setdefault(chap, []).append(
            {'name': name, 'code': code.strip(), 'full_title': title}
        )
    return jsonify(result)




# ══════════════════════════════════════════════════════════════
#  B) SAVE / SHARE — stockage JSON local
# ══════════════════════════════════════════════════════════════
import json, hashlib, pathlib

_SNIPPETS_FILE = pathlib.Path(__file__).parent / 'snippets.json'
_SNIPPETS_LOCK = threading.Lock()
MAX_SNIPPETS   = 10_000   # max snippets stockés

def _load_snippets() -> dict:
    try:
        if _SNIPPETS_FILE.exists():
            return json.loads(_SNIPPETS_FILE.read_text(encoding='utf-8'))
    except Exception:
        pass
    return {}

def _save_snippets(data: dict):
    try:
        _SNIPPETS_FILE.write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')
    except Exception:
        pass

@app.route('/api/save', methods=['POST'])
def api_save():
    err = _check_request()
    if err: return err
    data   = request.get_json(silent=True) or {}
    source, e = _clean_source(data.get('source', ''))
    if e: return jsonify({'error': e, 'id': None})
    title  = str(data.get('title', 'Sans titre'))[:80]

    # ID = 8 premiers chars du SHA256
    sid = hashlib.sha256(source.encode()).hexdigest()[:8]

    with _SNIPPETS_LOCK:
        snippets = _load_snippets()
        if len(snippets) >= MAX_SNIPPETS:
            # Purger les plus vieux (FIFO simple)
            oldest = sorted(snippets.keys())[: MAX_SNIPPETS // 10]
            for k in oldest: del snippets[k]
        snippets[sid] = {'code': source, 'title': title,
                         'ts': int(time.time())}
        _save_snippets(snippets)

    return jsonify({'id': sid, 'error': None})


@app.route('/api/load/<sid>', methods=['GET'])
def api_load(sid):
    # Valider l'ID : 8 chars hex uniquement
    if not sid or len(sid) != 8 or not all(c in '0123456789abcdef' for c in sid):
        return jsonify({'error': 'ID invalide', 'code': None}), 400
    with _SNIPPETS_LOCK:
        snippets = _load_snippets()
    snippet = snippets.get(sid)
    if not snippet:
        return jsonify({'error': 'Snippet introuvable', 'code': None}), 404
    return jsonify({'code': snippet['code'], 'title': snippet.get('title',''),
                    'error': None})


# Chargement depuis URL /?s=XXXX
@app.route('/s/<sid>')
def share_redirect(sid):
    return send_from_directory('static', 'index.html')


# ══════════════════════════════════════════════════════════════
#  C) MONITORING — stats + logs
# ══════════════════════════════════════════════════════════════
import os as _os

_ADMIN_KEY = os.environ.get('ADMIN_KEY', 'ziani_2904.')
_LOG_FILE     = pathlib.Path(__file__).parent / 'app.log'

# Compteurs en mémoire (réinitialisés au redémarrage)
_stats = {
    'start_time':   time.time(),
    'runs_total':   0,
    'runs_ok':      0,
    'runs_error':   0,
    'runs_timeout': 0,
    'rate_limited': 0,
    'last_errors':  [],       # liste des 20 dernières erreurs
    'exec_times':   [],       # derniers 200 temps d'exécution (ms)
}
_stats_lock = threading.Lock()

def _log(level: str, msg: str):
    """Écrit une ligne dans app.log avec timestamp."""
    line = f'[{time.strftime("%Y-%m-%d %Human:%M:%S")}] {level} {msg}\n'
    try:
        with _LOG_FILE.open('a', encoding='utf-8') as f:
            f.write(line)
    except Exception:
        pass

_EXPECTED_ERRORS = [
    "désactivé en version Web",   # ouvrir() bloqué
    "aucune entrée fournie",       # Lire() sans input
]

def _is_expected_error(err: str) -> bool:
    return err and any(x in err for x in _EXPECTED_ERRORS)

def _record_run(elapsed_ms: float, error: str | None, timeout: bool):
    with _stats_lock:
        _stats['runs_total'] += 1
        if timeout:
            _stats['runs_timeout'] += 1
        elif error and not _is_expected_error(error):
            # Seulement les vraies erreurs (pas les "fichiers désactivés" etc.)
            _stats['runs_error'] += 1
            _stats['last_errors'].append({'ts': int(time.time()), 'msg': error[:120]})
            _stats['last_errors'] = _stats['last_errors'][-20:]
        else:
            _stats['runs_ok'] += 1
        _stats['exec_times'].append(round(elapsed_ms))
        _stats['exec_times'] = _stats['exec_times'][-200:]


# ── Patch api_run pour recorder les stats ────────────────────
_orig_api_run = api_run.__wrapped__ if hasattr(api_run, '__wrapped__') else None

@app.route('/api/health', methods=['GET'])
def api_health():
    """Endpoint public — juste pour savoir si le serveur est vivant."""
    return jsonify({'status': 'ok',
                    'uptime_s': int(time.time() - _stats['start_time'])})


@app.route('/api/admin/stats', methods=['GET'])
def api_admin_stats():
    """Statistiques détaillées — protégées par ADMIN_KEY."""
    key = request.args.get('key', '')
    if not key or key != _ADMIN_KEY:
        return jsonify({'error': 'Non autorisé'}), 403

    with _stats_lock:
        times = _stats['exec_times']
        avg   = round(sum(times)/len(times)) if times else 0
        mx    = max(times) if times else 0
        snap  = {
            'uptime_s':     int(time.time() - _stats['start_time']),
            'runs_total':   _stats['runs_total'],
            'runs_ok':      _stats['runs_ok'],
            'runs_error':   _stats['runs_error'],
            'runs_timeout': _stats['runs_timeout'],
            'rate_limited': _stats['rate_limited'],
            'avg_exec_ms':  avg,
            'max_exec_ms':  mx,
            'last_errors':  list(_stats['last_errors']),
            'banned_ips':   _ban_list.ban_count(),
        }
    return jsonify(snap)


@app.route('/admin')
def admin_page():
    """Dashboard admin minimal (protégé côté JS par ADMIN_KEY)."""
    return send_from_directory('static', 'admin.html')

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

# ══════════════════════════════════════════════════════════════
#  GESTION DES ERREURS HTTP
# ══════════════════════════════════════════════════════════════
@app.errorhandler(413)
def _e413(_): return jsonify({'error': f'Requête trop grande (max {MAX_REQUEST_BYTES//1000} KB).'}), 413

@app.errorhandler(415)
def _e415(_): return jsonify({'error': 'Content-Type doit être application/json.'}), 415

@app.errorhandler(429)
def _e429(_): return jsonify({'error': 'Trop de requêtes. Réessayez dans une minute.'}), 429

@app.errorhandler(405)
def _e405(_): return jsonify({'error': 'Méthode non autorisée.'}), 405

@app.errorhandler(404)
def _e404(_): return jsonify({'error': 'Ressource introuvable.'}), 404

# ══════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════
if __name__ == '__main__':
    print("🔒 AlgoStudio Web (durci) — http://localhost:5000")
    print(f"   source={MAX_SOURCE_BYTES//1000}KB | timeout={EXEC_TIMEOUT_SEC}s | "
          f"output={MAX_OUTPUT_LINES}L | string={MAX_STRING_LEN//1000}K | "
          f"concurrent={MAX_CONCURRENT} | rate=30/min")
    app.run(debug=False, port=5000, host='127.0.0.1')
