
// STINT 2026 — 독립 백엔드 서버
// Q&A / 퀴즈 기록을 암호화하여 저장하고, 관리자만 전체 내용을 조회할 수 있습니다.
// 클로드와 무관하게 GitHub + Render(또는 Railway 등)에 별도 배포해서 사용합니다.
//
// 저장 방식: 컴파일이 필요 없는 JSON 파일 기반 저장소를 사용합니다.
// (better-sqlite3 같은 네이티브 모듈은 호스팅 환경에 따라 빌드가 실패할 수 있어 피했습니다.
//  Render 무료 플랜은 어차피 디스크가 영구 저장되지 않으므로 SQLite를 써도 이점이 없습니다.)
 
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const nodemailer = require("nodemailer");
 
const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(cors());
 
const PORT = process.env.PORT || 3000;
 
// ---------------------------------------------------------------------------
// 보안 설정
// ---------------------------------------------------------------------------
const ADMIN_SECRET = process.env.ADMIN_SECRET || "STINT26-Qna-7Kx2";
 
const ENCRYPTION_KEY = crypto
  .createHash("sha256")
  .update(process.env.ENCRYPTION_KEY || "please-change-this-key-before-deploy")
  .digest();
 
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
 
// 아주 단순한 IP 기반 요청 제한
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
// DB 설정 (JSON 파일 기반 — 별도 컴파일/설치 없이 어디서나 동작)
// 주의: Render 무료 플랜은 디스크가 영구 저장되지 않아 재배포 시 데이터가 초기화될 수 있습니다.
// 데이터를 계속 보존하려면 Render의 유료 Persistent Disk 또는 Supabase 같은 외부 DB 사용을 권장합니다.
// ---------------------------------------------------------------------------
const DB_FILE = path.join(__dirname, "stint2026-db.json");
 
function readDB() {
  try {
    if (!fs.existsSync(DB_FILE)) return { qna: [], quizResults: [] };
    const raw = fs.readFileSync(DB_FILE, "utf8");
    const data = JSON.parse(raw);
    return { qna: data.qna || [], quizResults: data.quizResults || [] };
  } catch (e) {
    return { qna: [], quizResults: [] };
  }
}
 
function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data), "utf8");
}
 
let nextQnaId = 1;
let nextQuizId = 1;
(() => {
  const data = readDB();
  nextQnaId = data.qna.reduce((m, r) => Math.max(m, r.id), 0) + 1;
  nextQuizId = data.quizResults.reduce((m, r) => Math.max(m, r.id), 0) + 1;
})();
 
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
  const data = readDB();
  const history = data.qna
    .filter((r) => r.identityHash === idHash)
    .sort((a, b) => a.ts - b.ts)
    .map((r) => ({
      question: decrypt(r.encQuestion),
      answer: decrypt(r.encAnswer),
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
  const data = readDB();
  data.qna.push({
    id: nextQnaId++,
    identityHash: hashIdentity(name, country, birth),
    encName: encrypt(name),
    encCountry: encrypt(country),
    encBirth: encrypt(birth),
    encQuestion: encrypt(question),
    encAnswer: encrypt(answer),
    ts: ts || Date.now(),
  });
  writeDB(data);
  res.json({ ok: true });
});
 
// 관리자 전용: 전체 Q&A 기록 조회 (질문 순서대로, 복호화하여 반환)
app.get("/api/admin/qna", requireAdmin, (req, res) => {
  const data = readDB();
  const list = [...data.qna]
    .sort((a, b) => a.ts - b.ts)
    .map((r) => ({
      name: decrypt(r.encName),
      country: decrypt(r.encCountry),
      birth: decrypt(r.encBirth),
      question: decrypt(r.encQuestion),
      answer: decrypt(r.encAnswer),
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
  const data = readDB();
  data.quizResults.push({
    id: nextQuizId++,
    identityHash: hashIdentity(name, country, birth),
    encName: encrypt(name),
    score,
    total,
    answers: answers.map((a) => ({ qIndex: a.qIndex, correct: !!a.correct })),
    ts: Date.now(),
  });
  writeDB(data);
  res.json({ ok: true });
});
 
// 공개 통계: 참여자 수, 평균 점수, 가장 많이 틀린 문제 (개인정보 없이 집계만 반환)
app.get("/api/quiz/stats", (req, res) => {
  const data = readDB();
  const count = data.quizResults.length;
  const avg = count > 0 ? data.quizResults.reduce((s, r) => s + r.score, 0) / count : 0;
 
  const wrongCounts = {};
  const answerCounts = {};
  for (const r of data.quizResults) {
    for (const a of r.answers || []) {
      answerCounts[a.qIndex] = (answerCounts[a.qIndex] || 0) + 1;
      if (!a.correct) wrongCounts[a.qIndex] = (wrongCounts[a.qIndex] || 0) + 1;
    }
  }
  const mostMissed = Object.keys(wrongCounts)
    .map((k) => ({ qIndex: Number(k), wrong: wrongCounts[k], total: answerCounts[k] || 0 }))
    .sort((a, b) => b.wrong - a.wrong)
    .slice(0, 10);
 
  res.json({ ok: true, count, avg, mostMissed });
});
 
// ---------------------------------------------------------------------------
// 관리자 코드 이메일 발송 (Gmail SMTP) — 선택 기능
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
