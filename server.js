// STINT 2026 — 독립 백엔드 서버
// Q&A / 퀴즈 기록을 암호화하여 DB(SQLite)에 저장하고, 관리자만 전체 내용을 조회할 수 있습니다.
// 클로드와 무관하게 GitHub + Render(또는 Railway 등)에 별도 배포해서 사용합니다.

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const path = require("path");
const Database = require("better-sqlite3");
const nodemailer = require("nodemailer");

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(cors()); // 필요 시 특정 도메인만 허용하도록 좁힐 수 있습니다 (README 참고)

const PORT = process.env.PORT || 3000;

// ---------------------------------------------------------------------------
// 보안 설정
// ---------------------------------------------------------------------------
// 관리자 코드: 프론트엔드 관리자 화면 잠금 해제 코드와 동일한 값을 여기에도 넣어주세요.
// 이 값을 아는 사람만 전체 Q&A/퀴즈 기록을 조회할 수 있습니다.
const ADMIN_SECRET = process.env.ADMIN_SECRET || "STINT26-Qna-7Kx2";

// 암호화 키: 반드시 배포 시 환경변수로 별도 지정하세요 (아래 기본값은 로컬 테스트용입니다).
const ENCRYPTION_KEY = crypto
  .createHash("sha256")
  .update(process.env.ENCRYPTION_KEY || "please-change-this-key-before-deploy")
  .digest(); // 어떤 길이의 문자열을 넣어도 항상 32바이트 키로 변환됨

const ALGO = "aes-256-gcm";

function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGO, ENCRYPTION_KEY, iv);
  const enc = Buffer.concat([cipher.update(String(text ?? ""), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString("base64");
}

function decrypt(b64) {
  try {
    const buf = Buffer.from(b64, "base64");
    const iv = buf.subarray(0, 12);
    const tag = buf.subarray(12, 28);
    const enc = buf.subarray(28);
    const decipher = crypto.createDecipheriv(ALGO, ENCRYPTION_KEY, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(enc), decipher.final()]).toString("utf8");
  } catch (e) {
    return "[복호화 실패]";
  }
}

function hashIdentity(name, country, birth) {
  const norm = `${String(name).trim()}|${String(country).trim()}|${String(birth).trim()}`.toLowerCase();
  return crypto.createHash("sha256").update(norm).digest("hex");
}

// 아주 단순한 IP 기반 요청 제한 (초당 과도한 요청으로부터 최소한의 보호)
const rateMap = new Map();
function rateLimit(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress || "unknown";
  const now = Date.now();
  const entry = rateMap.get(ip) || { count: 0, windowStart: now };
  if (now - entry.windowStart > 60_000) {
    entry.count = 0;
    entry.windowStart = now;
  }
  entry.count += 1;
  rateMap.set(ip, entry);
  if (entry.count > 60) {
    return res.status(429).json({ ok: false, error: "요청이 너무 많습니다. 잠시 후 다시 시도해 주세요." });
  }
  next();
}
app.use(rateLimit);

function requireAdmin(req, res, next) {
  const key = req.get("x-admin-key");
  if (!key || key !== ADMIN_SECRET) {
    return res.status(401).json({ ok: false, error: "관리자 인증이 필요합니다." });
  }
  next();
}

// ---------------------------------------------------------------------------
// DB 설정 (SQLite 파일 기반)
// 주의: Render 무료 플랜은 디스크가 영구 저장되지 않아 재배포 시 데이터가 초기화될 수 있습니다.
// 데이터를 계속 보존하려면 Render의 유료 Persistent Disk 또는 Supabase 같은 외부 DB 사용을 권장합니다.
// ---------------------------------------------------------------------------
const db = new Database(path.join(__dirname, "stint2026.db"));
db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS qna_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_hash TEXT NOT NULL,
    enc_name TEXT NOT NULL,
    enc_country TEXT NOT NULL,
    enc_birth TEXT NOT NULL,
    enc_question TEXT NOT NULL,
    enc_answer TEXT NOT NULL,
    ts INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_qna_identity ON qna_log(identity_hash);

  CREATE TABLE IF NOT EXISTS quiz_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_hash TEXT NOT NULL,
    enc_name TEXT NOT NULL,
    score INTEGER NOT NULL,
    total INTEGER NOT NULL,
    ts INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS quiz_answers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    result_id INTEGER NOT NULL,
    q_index INTEGER NOT NULL,
    correct INTEGER NOT NULL,
    FOREIGN KEY (result_id) REFERENCES quiz_results(id)
  );
`);

// ---------------------------------------------------------------------------
// Q&A API
// ---------------------------------------------------------------------------

// 로그인 겸 본인 기록 조회 (이름 + 국가 + 생년월일)
app.post("/api/login", (req, res) => {
  const { name, country, birth } = req.body || {};
  if (!name || !country || !birth) {
    return res.status(400).json({ ok: false, error: "이름, 국가, 생년월일을 모두 입력해 주세요." });
  }
  const idHash = hashIdentity(name, country, birth);
  const rows = db
    .prepare("SELECT * FROM qna_log WHERE identity_hash = ? ORDER BY ts ASC")
    .all(idHash);
  const history = rows.map((r) => ({
    question: decrypt(r.enc_question),
    answer: decrypt(r.enc_answer),
    ts: r.ts,
  }));
  res.json({ ok: true, identityHash: idHash, history });
});

// 새 질문/답변 기록 저장 (암호화하여 저장)
app.post("/api/ask", (req, res) => {
  const { name, country, birth, question, answer, ts } = req.body || {};
  if (!name || !country || !birth || !question || !answer) {
    return res.status(400).json({ ok: false, error: "필수 항목이 누락되었습니다." });
  }
  const idHash = hashIdentity(name, country, birth);
  db.prepare(
    `INSERT INTO qna_log (identity_hash, enc_name, enc_country, enc_birth, enc_question, enc_answer, ts)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(idHash, encrypt(name), encrypt(country), encrypt(birth), encrypt(question), encrypt(answer), ts || Date.now());
  res.json({ ok: true });
});

// 관리자 전용: 전체 Q&A 기록 조회 (질문 순서대로, 복호화하여 반환)
app.get("/api/admin/qna", requireAdmin, (req, res) => {
  const rows = db.prepare("SELECT * FROM qna_log ORDER BY ts ASC").all();
  const list = rows.map((r) => ({
    name: decrypt(r.enc_name),
    country: decrypt(r.enc_country),
    birth: decrypt(r.enc_birth),
    question: decrypt(r.enc_question),
    answer: decrypt(r.enc_answer),
    ts: r.ts,
  }));
  res.json({ ok: true, count: list.length, records: list });
});

// ---------------------------------------------------------------------------
// 퀴즈 API
// ---------------------------------------------------------------------------

app.post("/api/quiz/submit", (req, res) => {
  const { name, country, birth, score, total, answers } = req.body || {};
  if (!name || !country || !birth || typeof score !== "number" || typeof total !== "number" || !Array.isArray(answers)) {
    return res.status(400).json({ ok: false, error: "필수 항목이 누락되었습니다." });
  }
  const idHash = hashIdentity(name, country, birth);
  const insertResult = db.prepare(
    `INSERT INTO quiz_results (identity_hash, enc_name, score, total, ts) VALUES (?, ?, ?, ?, ?)`
  );
  const insertAnswer = db.prepare(
    `INSERT INTO quiz_answers (result_id, q_index, correct) VALUES (?, ?, ?)`
  );
  const tx = db.transaction(() => {
    const info = insertResult.run(idHash, encrypt(name), score, total, Date.now());
    const resultId = info.lastInsertRowid;
    for (const a of answers) {
      insertAnswer.run(resultId, a.qIndex, a.correct ? 1 : 0);
    }
  });
  tx();
  res.json({ ok: true });
});

// 공개 통계: 참여자 수, 평균 점수, 가장 많이 틀린 문제 (개인정보 없이 집계만 반환)
app.get("/api/quiz/stats", (req, res) => {
  const countRow = db.prepare("SELECT COUNT(*) AS c, AVG(score) AS avg FROM quiz_results").get();
  const wrongRows = db
    .prepare(
      `SELECT q_index AS qIndex,
              SUM(CASE WHEN correct = 0 THEN 1 ELSE 0 END) AS wrong,
              COUNT(*) AS total
       FROM quiz_answers
       GROUP BY q_index
       ORDER BY wrong DESC
       LIMIT 10`
    )
    .all();
  res.json({
    ok: true,
    count: countRow.c || 0,
    avg: countRow.avg || 0,
    mostMissed: wrongRows.filter((r) => r.wrong > 0),
  });
});

// ---------------------------------------------------------------------------
// 관리자 코드 이메일 발송 (Gmail SMTP)
// ---------------------------------------------------------------------------
const GMAIL_USER = process.env.GMAIL_USER;
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD;
const RECIPIENT = "tesoro319@gmail.com";

const transporter = GMAIL_USER
  ? nodemailer.createTransport({ service: "gmail", auth: { user: GMAIL_USER, pass: GMAIL_APP_PASSWORD } })
  : null;

app.post("/api/send-admin-code", async (req, res) => {
  if (!transporter) return res.status(500).json({ ok: false, error: "이메일 서버가 설정되지 않았습니다." });
  try {
    await transporter.sendMail({
      from: `"STINT 2026" <${GMAIL_USER}>`,
      to: RECIPIENT,
      subject: "[STINT 2026] 관리자 접속코드 안내",
      text: `관리자 접속코드: ${ADMIN_SECRET}\n\n본인 확인 후 이 코드로 관리자 화면에 로그인하세요.`,
    });
    res.json({ ok: true });
  } catch (e) {
    console.error("이메일 발송 오류:", e);
    res.status(500).json({ ok: false, error: "이메일 발송에 실패했습니다." });
  }
});

app.get("/", (req, res) => res.send("STINT 2026 백엔드 서버가 정상 동작 중입니다."));

app.listen(PORT, () => console.log(`서버 실행 중: 포트 ${PORT}`));
