<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

$origin = getenv('APP_ORIGIN') ?: '';
if ($origin !== '' && isset($_SERVER['HTTP_ORIGIN']) && hash_equals($origin, $_SERVER['HTTP_ORIGIN'])) {
  header('Access-Control-Allow-Origin: ' . $origin);
  header('Access-Control-Allow-Credentials: true');
  header('Vary: Origin');
}
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-CSRF-Token');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

function respond(array $data, int $status = 200): never {
  http_response_code($status); echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES); exit;
}
function input(): array {
  $data = json_decode(file_get_contents('php://input') ?: '[]', true);
  return is_array($data) ? $data : $_POST;
}
function db(): PDO {
  static $pdo = null;
  if ($pdo instanceof PDO) return $pdo;
  $host = getenv('DB_HOST'); $name = getenv('DB_NAME'); $user = getenv('DB_USER'); $pass = getenv('DB_PASSWORD');
  if (!$host || !$name || !$user) respond(['error'=>'database_not_configured'], 503);
  $port = getenv('DB_PORT') ?: '3306';
  $options = [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES=>false];
   $ca = trim((string)(getenv('DB_SSL_CA') ?: ''));
  if ($ca === '') respond(['error'=>'database_tls_ca_not_configured'], 503);
  // Vercel variables may be pasted with literal \n sequences instead of line breaks.
  $ca = str_replace(["\\r\\n", "\\n", "\\r"], ["\n", "\n", "\r"], $ca);
  $ca = str_replace(["\r\n", "\r"], "\n", $ca);
  if (!str_contains($ca, '-----BEGIN CERTIFICATE-----') || !str_contains($ca, '-----END CERTIFICATE-----')) {
    respond(['error'=>'database_tls_ca_invalid'], 503);
  }
  $options[\Pdo\Mysql::ATTR_SSL_CA] = $caPath;
  $options[\Pdo\Mysql::ATTR_SSL_VERIFY_SERVER_CERT] = true;
  $pdo = new PDO("mysql:host=$host;port=$port;dbname=$name;charset=utf8mb4", $user, $pass ?: '', $options);
  return $pdo;
}
function csrf(): string {
  if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
  return $_SESSION['csrf'];
}
function user(): ?array { return $_SESSION['user'] ?? null; }
function requireUser(): array { $u=user(); if (!$u) respond(['error'=>'login_required'],401); return $u; }
function requireRole(array $roles): array { $u=requireUser(); if (!in_array($u['role'],$roles,true)) respond(['error'=>'forbidden'],403); return $u; }
function checkCsrf(): void {
  if ($_SERVER['REQUEST_METHOD'] !== 'POST' || in_array($_GET['action'] ?? '', ['login','register','bootstrap-admin'], true)) return;
  $sent = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
  if (!$sent || !hash_equals(csrf(), $sent)) respond(['error'=>'csrf_failed'],403);
}
function cleanUser(array $row): array { return ['id'=>(int)$row['id'],'email'=>$row['email'],'displayName'=>$row['display_name'],'role'=>$row['role']]; }

final class DbSessionHandler implements SessionHandlerInterface {
  public function open(string $path,string $name):bool{return true;}
  public function close():bool{return true;}
  public function read(string $id):string|false{$q=db()->prepare('SELECT payload FROM app_sessions WHERE session_id=? AND expires_at>?');$q->execute([$id,time()]);$v=$q->fetchColumn();return $v===false?'':(string)$v;}
  public function write(string $id,string $data):bool{$q=db()->prepare('INSERT INTO app_sessions(session_id,payload,expires_at) VALUES(?,?,?) ON DUPLICATE KEY UPDATE payload=VALUES(payload),expires_at=VALUES(expires_at)');return $q->execute([$id,$data,time()+1800]);}
  public function destroy(string $id):bool{$q=db()->prepare('DELETE FROM app_sessions WHERE session_id=?');return $q->execute([$id]);}
  public function gc(int $max_lifetime):int|false{$q=db()->prepare('DELETE FROM app_sessions WHERE expires_at<?');$q->execute([time()]);return $q->rowCount();}
}

session_name('maria_session');
session_set_cookie_params(['lifetime'=>0,'path'=>'/','secure'=>true,'httponly'=>true,'samesite'=>'Lax']);
session_set_save_handler(new DbSessionHandler(),true);
try { session_start(); } catch (Throwable $e) { error_log('Session/database connection failed: ' . $e->getMessage()); respond(['error'=>'database_connection_failed'],503); }
$action = $_GET['action'] ?? '';
try {
  if ($action === 'csrf') respond(['csrf'=>csrf(),'user'=>user()]);
  if ($action === 'register') {
    $d=input(); $email=strtolower(trim((string)($d['email']??''))); $name=trim((string)($d['displayName']??'')); $password=(string)($d['password']??'');
    if (!filter_var($email,FILTER_VALIDATE_EMAIL)||strlen($password)<10||mb_strlen($name)<2||mb_strlen($name)>80) respond(['error'=>'invalid_registration'],422);
    $q=db()->prepare("INSERT INTO users(email,display_name,password_hash) VALUES(?,?,?)");
    try{$q->execute([$email,$name,password_hash($password,PASSWORD_DEFAULT)]);}catch(PDOException $e){if((string)$e->getCode()==='23000')respond(['error'=>'email_exists'],409);throw $e;}
    session_regenerate_id(true); $_SESSION['user']=['id'=>(int)db()->lastInsertId(),'email'=>$email,'displayName'=>$name,'role'=>'listener']; csrf(); respond(['user'=>user(),'csrf'=>csrf()],201);
  }
  if ($action === 'login') {
    $d=input(); $q=db()->prepare('SELECT * FROM users WHERE email=? LIMIT 1'); $q->execute([strtolower(trim((string)($d['email']??'')))]); $row=$q->fetch();
    if (!$row || !password_verify((string)($d['password']??''),$row['password_hash'])) respond(['error'=>'invalid_credentials'],401);
    session_regenerate_id(true); $_SESSION['user']=cleanUser($row); csrf(); respond(['user'=>user(),'csrf'=>csrf()]);
  }
  if ($action === 'bootstrap-admin') {
    $d=input(); $key=(string)($d['setupKey']??''); $expected=getenv('ADMIN_SETUP_KEY')?:'';
    if ($expected===''||!hash_equals($expected,$key)) respond(['error'=>'invalid_setup_key'],403);
    $count=(int)db()->query("SELECT COUNT(*) FROM users WHERE role='admin'")->fetchColumn(); if($count>0)respond(['error'=>'admin_already_exists'],409);
    $email=strtolower(trim((string)($d['email']??'')));$name=trim((string)($d['displayName']??''));$password=(string)($d['password']??'');
    if(!filter_var($email,FILTER_VALIDATE_EMAIL)||strlen($password)<12||mb_strlen($name)<2)respond(['error'=>'invalid_admin_data'],422);
    $q=db()->prepare("INSERT INTO users(email,display_name,password_hash,role) VALUES(?,?,?,'admin')");$q->execute([$email,$name,password_hash($password,PASSWORD_DEFAULT)]);
    putenv('ADMIN_SETUP_KEY='); respond(['ok'=>true,'message'=>'admin_created_remove_setup_key_from_vercel']);
  }
  if ($action === 'logout') { checkCsrf(); $_SESSION=[]; session_destroy(); respond(['ok'=>true]); }
  if ($action === 'me') { respond(['user'=>user(),'csrf'=>csrf()]); }
  if ($action === 'songs') {
    $songs=db()->query('SELECT id,title,artist,audio_url AS audioUrl,cover_url AS coverUrl,duration_seconds AS duration FROM songs WHERE published=1 ORDER BY id DESC')->fetchAll();
    respond(['songs'=>$songs]);
  }
  if ($action === 'lyrics') {
    $id=max(0,(int)($_GET['song']??0));$q=db()->prepare('SELECT line_no AS line,start_ms AS startMs,text FROM lyrics WHERE song_id=? ORDER BY start_ms,line_no');$q->execute([$id]);respond(['lyrics'=>$q->fetchAll()]);
  }
  if ($action === 'save-song') {
    $u=requireRole(['admin','editor']);checkCsrf();$d=input();$id=(int)($d['id']??0);$title=trim((string)($d['title']??''));$audio=trim((string)($d['audioUrl']??''));$cover=trim((string)($d['coverUrl']??''));
    if($title===''||!filter_var($audio,FILTER_VALIDATE_URL)||!in_array(parse_url($audio,PHP_URL_SCHEME),['https'],true))respond(['error'=>'invalid_song'],422);
    if($id){$q=db()->prepare('UPDATE songs SET title=?,artist=?,audio_url=?,cover_url=?,duration_seconds=? WHERE id=?');$q->execute([$title,trim((string)($d['artist']??'Maria')),$audio,$cover?:null,max(0,(int)($d['duration']??0))?:null,$id]);}
    else{$q=db()->prepare('INSERT INTO songs(title,artist,audio_url,cover_url,duration_seconds,created_by) VALUES(?,?,?,?,?,?)');$q->execute([$title,trim((string)($d['artist']??'Maria')),$audio,$cover?:null,max(0,(int)($d['duration']??0))?:null,$u['id']]);$id=(int)db()->lastInsertId();}
    respond(['ok'=>true,'id'=>$id]);
  }
  if ($action === 'save-lyrics') {
    requireRole(['admin','editor']);checkCsrf();$d=input();$song=(int)($d['songId']??0);$lines=$d['lines']??[];if(!$song||!is_array($lines)||count($lines)>3000)respond(['error'=>'invalid_lyrics'],422);
    $pdo=db();$pdo->beginTransaction();$q=$pdo->prepare('DELETE FROM lyrics WHERE song_id=?');$q->execute([$song]);$ins=$pdo->prepare('INSERT INTO lyrics(song_id,line_no,start_ms,text) VALUES(?,?,?,?)');
    foreach($lines as $i=>$line){$txt=trim((string)($line['text']??''));$ms=max(0,(int)($line['startMs']??0));if($txt!=='')$ins->execute([$song,$i+1,$ms,mb_substr($txt,0,1000)]);}$pdo->commit();respond(['ok'=>true]);
  }
  if ($action === 'player') {
    if($_SERVER['REQUEST_METHOD']==='GET'){$s=db()->query('SELECT song_id AS songId,position_ms AS positionMs,is_playing AS isPlaying,UNIX_TIMESTAMP(updated_at)*1000 AS updatedAt FROM player_state WHERE id=1')->fetch();respond(['state'=>$s]);}
    requireUser();checkCsrf();$d=input();$song=max(0,(int)($d['songId']??0));$q=db()->prepare('UPDATE player_state SET song_id=?,position_ms=?,is_playing=? WHERE id=1');$q->execute([$song?:null,max(0,(int)($d['positionMs']??0)),!empty($d['isPlaying'])?1:0]);respond(['ok'=>true]);
  }
  if ($action === 'users') { requireRole(['admin']);$rows=db()->query('SELECT id,email,display_name AS displayName,role,created_at AS createdAt FROM users ORDER BY created_at DESC LIMIT 1000')->fetchAll();respond(['users'=>$rows]); }
  if ($action === 'set-role') {
    requireRole(['admin']);checkCsrf();$d=input();$id=(int)($d['userId']??0);$role=(string)($d['role']??'');if(!$id||!in_array($role,['listener','editor'],true))respond(['error'=>'invalid_role'],422);$q=db()->prepare("UPDATE users SET role=? WHERE id=? AND role<>'admin'");$q->execute([$role,$id]);respond(['ok'=>true]);
  }
  respond(['error'=>'unknown_action'],404);
} catch (Throwable $e) { error_log((string)$e); respond(['error'=>'server_error'],500); }
