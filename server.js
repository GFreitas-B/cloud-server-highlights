const express = require('express');
const WebSocket = require('ws');
const http = require('http');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const initSqlJs = require('sql.js');
const { Resend } = require('resend');
const {
  S3Client,
  PutObjectCommand,
  ListObjectsV2Command,
  GetObjectCommand,
  DeleteObjectCommand
} = require('@aws-sdk/client-s3');

const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 4000;

// ─── WEBSOCKET ─────────────────────────
const wss = new WebSocket.Server({ server });

const clientes = new Set();

wss.on('connection', (ws) => {
  clientes.add(ws);

  console.log('📱 Cliente conectado no WebSocket');

  ws.on('close', () => {
    clientes.delete(ws);
    console.log('❌ Cliente desconectado');
  });
});

function notificarNovoClipe(clipe) {
  const mensagem = JSON.stringify({
    tipo: 'novo_clipe',
    clipe,
  });

  clientes.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(mensagem);
    }
  });
}

// ─── MIDDLEWARES ─────────────────────────
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type', 'x-api-key', 'Authorization'],
}));

app.use(express.json());

// ─── BANCO DE DADOS ─────────────────────────
const DB_PATH = './highlights.db';

let db;

async function iniciarBanco() {
  const SQL = await initSqlJs();

  if (fs.existsSync(DB_PATH)) {
    const buffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buffer);
  } else {
    db = new SQL.Database();
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nome TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      senha TEXT NOT NULL,
      verificado INTEGER DEFAULT 0,
      criado_em DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS codigos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      codigo TEXT NOT NULL,
      tipo TEXT NOT NULL,
      expira_em DATETIME NOT NULL,
      usado INTEGER DEFAULT 0
    )
  `);

  salvarBanco();

  console.log('[DB] Banco de dados iniciado!');
}

function salvarBanco() {
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

function dbRun(sql, params = []) {
  db.run(sql, params);
  salvarBanco();
}

function dbGet(sql, params = []) {
  const stmt = db.prepare(sql);

  stmt.bind(params);

  if (stmt.step()) {
    const row = stmt.getAsObject();
    stmt.free();
    return row;
  }

  stmt.free();
  return null;
}

// ─── RESEND ─────────────────────────
const resend = new Resend(process.env.RESEND_API_KEY);

async function enviarEmail(para, assunto, html) {
  await resend.emails.send({
    from: 'Highlights <noreply@highlights-replay.com.br>',
    to: para,
    subject: assunto,
    html,
  });
}

function gerarCodigo() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ─── MIDDLEWARES AUTH ─────────────────────────
function autenticar(req, res, next) {
  const chave = req.headers['x-api-key'];

  if (!chave || chave !== process.env.API_KEY) {
    return res.status(401).json({ erro: 'Não autorizado' });
  }

  next();
}

function autenticarToken(req, res, next) {
  const auth = req.headers['authorization'];

  if (!auth) {
    return res.status(401).json({ erro: 'Token não fornecido' });
  }

  const token = auth.replace('Bearer ', '');

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.usuario = decoded;
    next();
  } catch {
    return res.status(401).json({ erro: 'Token inválido ou expirado' });
  }
}

// ─── R2 CLIENT ─────────────────────────
const r2 = new S3Client({
  region: 'auto',
  endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: process.env.R2_ACCESS_KEY_ID,
    secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
  },
});

const BUCKET = process.env.R2_BUCKET_NAME;

// ─── MULTER ─────────────────────────
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 200 * 1024 * 1024,
  },

  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'video/mp4') {
      cb(null, true);
    } else {
      cb(new Error('Apenas arquivos MP4 são aceitos'));
    }
  }
});

// ─── STATUS ─────────────────────────
app.get('/status', (req, res) => {
  res.json({
    status: 'online',
    timestamp: new Date(),
    websocket_clients: clientes.size,
  });
});

// ─── AUTH: CADASTRO ─────────────────────────
app.post('/auth/cadastro', async (req, res) => {
  try {
    const { nome, email, senha } = req.body;

    if (!nome || !email || !senha) {
      return res.status(400).json({
        erro: 'Preencha todos os campos'
      });
    }

    if (senha.length < 6) {
      return res.status(400).json({
        erro: 'A senha deve ter pelo menos 6 caracteres'
      });
    }

    const existente = dbGet(
      'SELECT id FROM usuarios WHERE email = ?',
      [email]
    );

    if (existente) {
      return res.status(400).json({
        erro: 'Email já cadastrado'
      });
    }

    const hash = await bcrypt.hash(senha, 10);

    dbRun(
      'INSERT INTO usuarios (nome, email, senha) VALUES (?, ?, ?)',
      [nome, email, hash]
    );

    const codigo = gerarCodigo();

    const expira = new Date(
      Date.now() + 15 * 60 * 1000
    ).toISOString();

    dbRun(
      'INSERT INTO codigos (email, codigo, tipo, expira_em) VALUES (?, ?, ?, ?)',
      [email, codigo, 'verificacao', expira]
    );

    await enviarEmail(
      email,
      'Verifique seu email - Highlights',
      `
      <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; background: #111; color: #fff; padding: 32px; border-radius: 16px;">
        <div style="text-align: center; margin-bottom: 24px;">
          <span style="background: #FFD600; color: #111; padding: 8px 16px; border-radius: 8px; font-weight: bold; font-size: 20px;">
            ▶ Highlights
          </span>
        </div>

        <h2 style="text-align: center; color: #fff;">
          Bem-vindo, ${nome}!
        </h2>

        <p style="color: #888; text-align: center;">
          Use o código abaixo para verificar seu email:
        </p>

        <div style="background: #1a1a1a; border: 2px solid #FFD600; border-radius: 12px; padding: 24px; text-align: center; margin: 24px 0;">
          <span style="font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #FFD600;">
            ${codigo}
          </span>
        </div>

        <p style="color: #555; text-align: center; font-size: 13px;">
          Este código expira em 15 minutos.
        </p>
      </div>
      `
    );

    res.json({
      ok: true,
      mensagem: 'Código enviado para o email'
    });

  } catch (err) {
    console.error('Erro cadastro:', err);

    res.status(500).json({
      erro: 'Erro ao cadastrar'
    });
  }
});

// ─── LOGIN ─────────────────────────
app.post('/auth/login', async (req, res) => {
  try {
    const { email, senha } = req.body;

    const usuario = dbGet(
      'SELECT * FROM usuarios WHERE email = ?',
      [email]
    );

    if (!usuario) {
      return res.status(400).json({
        erro: 'Email ou senha incorretos'
      });
    }

    if (!usuario.verificado) {
      return res.status(400).json({
        erro: 'Email não verificado'
      });
    }

    const senhaCorreta = await bcrypt.compare(
      senha,
      usuario.senha
    );

    if (!senhaCorreta) {
      return res.status(400).json({
        erro: 'Email ou senha incorretos'
      });
    }

    const token = jwt.sign(
      {
        id: usuario.id,
        email: usuario.email,
        nome: usuario.nome,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: '7d',
      }
    );

    res.json({
      ok: true,
      token,
      usuario: {
        id: usuario.id,
        nome: usuario.nome,
        email: usuario.email,
      }
    });

  } catch (err) {
    console.error('Erro login:', err);

    res.status(500).json({
      erro: 'Erro ao fazer login'
    });
  }
});

// ─── UPLOAD ─────────────────────────
app.post(
  '/upload',
  autenticar,
  upload.single('file'),
  async (req, res) => {

    try {
      const file = req.file;
      const cameraId = req.body.camera_id;

      if (!file) {
        return res.status(400).json({
          erro: 'Arquivo não enviado'
        });
      }

      const ext = path.extname(file.originalname);

      const nome = `${Date.now()}_${uuidv4()}${ext}`;

      await r2.send(new PutObjectCommand({
        Bucket: BUCKET,
        Key: nome,
        Body: file.buffer,
        ContentType: file.mimetype,
      }));

      const novoClipe = {
        nome,
        url: `${process.env.R2_PUBLIC_URL}/${nome}`,
        tamanho: file.size,
        criado: new Date(),
        camera_id: cameraId,
      };

      console.log('📥 Upload enviado ao R2:', nome);

      // 🔥 NOTIFICA TODOS OS CLIENTES EM TEMPO REAL
      notificarNovoClipe(novoClipe);

      res.json({
        ok: true,
        ...novoClipe,
      });

    } catch (err) {
      console.error('Erro upload:', err);

      res.status(500).json({
        erro: 'Erro no upload'
      });
    }
  }
);

// ─── LISTAR CLIPES ─────────────────────────
app.get('/clips', autenticarToken, async (req, res) => {
  try {

    let arquivos = [];
    let continuationToken = undefined;

    do {

      const data = await r2.send(
        new ListObjectsV2Command({
          Bucket: BUCKET,
          ContinuationToken: continuationToken,
        })
      );

      const pagina = (data.Contents || [])
        .filter(f => f.Key.endsWith('.mp4'))
        .map(f => ({
          nome: f.Key,
          url: `${process.env.R2_PUBLIC_URL}/${f.Key}`,
          tamanho: f.Size,
          criado: f.LastModified,
        }));

      arquivos = arquivos.concat(pagina);

      continuationToken = data.IsTruncated
        ? data.NextContinuationToken
        : undefined;

    } while (continuationToken);

    arquivos.sort(
      (a, b) => new Date(b.criado) - new Date(a.criado)
    );

    res.json(arquivos);

  } catch (err) {
    console.error('Erro ao listar:', err);

    res.status(500).json({
      erro: 'Erro ao listar clipes'
    });
  }
});

// ─── DELETAR CLIPE ─────────────────────────
app.delete('/clips/:nome', autenticarToken, async (req, res) => {
  try {

    await r2.send(
      new DeleteObjectCommand({
        Bucket: BUCKET,
        Key: req.params.nome,
      })
    );

    res.json({
      ok: true
    });

  } catch (err) {
    console.error('Erro ao deletar:', err);

    res.status(500).json({
      erro: 'Erro ao deletar'
    });
  }
});

// ─── URL ASSINADA ─────────────────────────
app.get('/clips/:nome/signed', autenticarToken, async (req, res) => {
  try {

    const url = await getSignedUrl(
      r2,
      new GetObjectCommand({
        Bucket: BUCKET,
        Key: req.params.nome,
      }),
      {
        expiresIn: 3600,
      }
    );

    res.json({ url });

  } catch (err) {
    console.error('Erro ao gerar URL:', err);

    res.status(500).json({
      erro: 'Erro ao gerar URL assinada'
    });
  }
});

// ─── START ─────────────────────────
iniciarBanco().then(() => {

  server.listen(PORT, () => {
    console.log(`☁️ Cloud server rodando na porta ${PORT}`);
  });

});