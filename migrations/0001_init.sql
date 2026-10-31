-- 0001_init: 核心表结构
-- 所有查询均通过参数化语句访问，禁止字符串拼接。

CREATE TABLE IF NOT EXISTS users (
  id              TEXT PRIMARY KEY,               -- 随机 UUID
  email           TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash   TEXT NOT NULL,                  -- base64(PBKDF2-SHA256 derived key)
  password_salt   TEXT NOT NULL,                  -- base64(16 bytes random)
  password_iter   INTEGER NOT NULL,               -- 迭代次数，便于未来升级
  email_verified  INTEGER NOT NULL DEFAULT 0 CHECK (email_verified IN (0,1)),
  status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  failed_logins   INTEGER NOT NULL DEFAULT 0,
  locked_until    INTEGER,                        -- unix seconds
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash  TEXT PRIMARY KEY,                   -- SHA-256(session token)，明文 token 不入库
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_token  TEXT NOT NULL,
  ip_hash     TEXT,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS email_verifications (
  token_hash  TEXT PRIMARY KEY,                   -- SHA-256(验证 token)
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER,
  created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sites (
  id            TEXT PRIMARY KEY,                 -- 随机不可猜测 ID（base32, 128 bit）
  owner_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name          TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
  status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','deleted')),
  active_prefix TEXT,                             -- 当前生效的 存储前缀（manifest 原子切换）
  total_bytes   INTEGER NOT NULL DEFAULT 0,
  file_count    INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sites_owner ON sites(owner_id);

CREATE TABLE IF NOT EXISTS files (
  site_id      TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  path         TEXT NOT NULL,                     -- 规范化后的相对路径，如 css/app.css
  storage_key       TEXT NOT NULL,                     -- 服务端生成，不来自用户输入
  size         INTEGER NOT NULL CHECK (size >= 0),
  sha256       TEXT NOT NULL,
  content_type TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  PRIMARY KEY (site_id, path)
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_id    TEXT,                               -- 可为空（匿名事件，如登录失败）
  action      TEXT NOT NULL,
  target      TEXT,
  ip_hash     TEXT,
  result      TEXT NOT NULL CHECK (result IN ('ok','denied','error')),
  created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);
