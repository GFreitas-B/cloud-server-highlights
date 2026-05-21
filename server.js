const express = require('express');
const helmet = require('helmet');
const WebSocket = require('ws');
const http = require('http');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');
const { Resend } = require('resend');
const {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand
} = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

const app = express();
app.set('trust proxy', 1);

const server = http.createServer(app);
const PORT = process.env.PORT || 4000;

// ─── WEBSOCKET ─────────────────────────
const wss = new WebSocket.Server({ server });
const clientesWs = new Set();

wss.on('connection', (ws) => {
  clientesWs.add(ws);
  console.log('📱 Cliente conectado no WebSocket');

  ws.on('close', () => {
    clientesWs.delete(ws);
    console.log('❌ Cliente desconectado');
  });
});

function notificarNovoClipe(clipe) {
  const mensagem = JSON.stringify({
    tipo: 'novo_clipe',
    clipe,
  });

  clientesWs.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(mensagem);
    }
  });
}

// ─── MIDDLEWARES ─────────────────────────
app.use(cors({
  origin: [
    'http://localhost:5173',
    'https://highlights-replay.com.br',
    'https://www.highlights-replay.com.br'
  ],
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key'],
}));

app.use(express.json());

function autenticarAdmin(req, res, next) {
  if (req.usuario.role !== 'admin') {
    return res.status(403).json({ erro: 'Acesso restrito ao administrador' });
  }

  next();
}

app.use(helmet({
  crossOriginResourcePolicy: false,
}));

// ─── BANCO ─────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

async function iniciarBanco() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id SERIAL PRIMARY KEY,
      role TEXT DEFAULT 'usuario',
      nome TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      senha TEXT NOT NULL,
      verificado INTEGER DEFAULT 0,
      criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
  ALTER TABLE usuarios
  ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'usuario'
`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS clientes (
      id SERIAL PRIMARY KEY,
      nome TEXT NOT NULL,
      ativo BOOLEAN DEFAULT true,
      criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
  ALTER TABLE clientes
  ADD COLUMN IF NOT EXISTS imagem_url TEXT
`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS usuarios_clientes (
      id SERIAL PRIMARY KEY,
      usuario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
      cliente_id INTEGER NOT NULL REFERENCES clientes(id) ON DELETE CASCADE,
      papel TEXT DEFAULT 'admin',
      criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(usuario_id, cliente_id)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS quadras (
      id SERIAL PRIMARY KEY,
      cliente_id INTEGER NOT NULL REFERENCES clientes(id) ON DELETE CASCADE,
      nome TEXT NOT NULL,
      ativa BOOLEAN DEFAULT true,
      criada_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS cameras (
      id SERIAL PRIMARY KEY,
      cliente_id INTEGER NOT NULL REFERENCES clientes(id) ON DELETE CASCADE,
      quadra_id INTEGER NOT NULL REFERENCES quadras(id) ON DELETE CASCADE,
      nome TEXT NOT NULL,
      api_key TEXT UNIQUE NOT NULL,
      ativa BOOLEAN DEFAULT true,
      criada_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS clips (
      id SERIAL PRIMARY KEY,
      nome TEXT UNIQUE NOT NULL,
      cliente_id INTEGER NOT NULL REFERENCES clientes(id) ON DELETE CASCADE,
      quadra_id INTEGER NOT NULL REFERENCES quadras(id) ON DELETE CASCADE,
      camera_id INTEGER REFERENCES cameras(id) ON DELETE SET NULL,
      criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS codigos (
      id SERIAL PRIMARY KEY,
      email TEXT NOT NULL,
      codigo TEXT NOT NULL,
      tipo TEXT NOT NULL,
      expira_em TIMESTAMP NOT NULL,
      usado INTEGER DEFAULT 0
    )
  `);

  await pool.query(`
  CREATE TABLE IF NOT EXISTS servidores_locais (
    id SERIAL PRIMARY KEY,
    cliente_id INTEGER NOT NULL REFERENCES clientes(id) ON DELETE CASCADE,
    nome TEXT NOT NULL,
    token TEXT UNIQUE NOT NULL,
    online BOOLEAN DEFAULT false,
    cpu_percent NUMERIC DEFAULT 0,
    ram_percent NUMERIC DEFAULT 0,
    disco_percent NUMERIC DEFAULT 0,
    ultimo_ping TIMESTAMP,
    criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`);

  await pool.query(`
  ALTER TABLE cameras
  ADD COLUMN IF NOT EXISTS online BOOLEAN DEFAULT false
`);

  await pool.query(`
  ALTER TABLE cameras
  ADD COLUMN IF NOT EXISTS rtsp_ok BOOLEAN DEFAULT false
`);

  await pool.query(`
  ALTER TABLE cameras
  ADD COLUMN IF NOT EXISTS replay_ok BOOLEAN DEFAULT false
`);

  await pool.query(`
  ALTER TABLE cameras
  ADD COLUMN IF NOT EXISTS ultimo_ping TIMESTAMP
`);

  await pool.query(`
  CREATE TABLE IF NOT EXISTS licenses (
    id SERIAL PRIMARY KEY,
    cliente_id INTEGER NOT NULL REFERENCES clientes(id) ON DELETE CASCADE,
    license_key TEXT UNIQUE NOT NULL,
    status TEXT DEFAULT 'active',
    max_quadras INTEGER DEFAULT 1,
    max_cameras INTEGER DEFAULT 2,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`);

  await pool.query(`
  ALTER TABLE licenses
  ADD COLUMN IF NOT EXISTS hardware_id TEXT
`);

  await pool.query(`
  ALTER TABLE licenses
  ADD COLUMN IF NOT EXISTS activated_at TIMESTAMP
`);

  await pool.query(`
  ALTER TABLE licenses
  ADD COLUMN IF NOT EXISTS last_check_at TIMESTAMP
`);

  console.log('[DB] Banco de dados PostgreSQL iniciado!');
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

// ─── AUTH HELPERS ─────────────────────────
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

async function autenticarCamera(req, res, next) {
  try {
    const apiKey = req.headers['x-api-key'];

    if (!apiKey) {
      return res.status(401).json({ erro: 'API key não fornecida' });
    }

    const resultado = await pool.query(
      `
      SELECT id, cliente_id, quadra_id, nome
      FROM cameras
      WHERE api_key = $1 AND ativa = true
      LIMIT 1
      `,
      [apiKey]
    );

    if (resultado.rows.length === 0) {
      return res.status(401).json({ erro: 'API key inválida' });
    }

    req.camera = resultado.rows[0];
    next();
  } catch (err) {
    console.error('Erro ao autenticar câmera:', err);
    res.status(500).json({ erro: 'Erro de autenticação da câmera' });
  }
}

// ─── R2 ─────────────────────────
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

// ─── RATE LIMIT ─────────────────────────
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: {
    erro: 'Muitas tentativas de login. Tente novamente em 15 minutos.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const resetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: {
    erro: 'Muitas solicitações. Aguarde alguns minutos.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const verifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: {
    erro: 'Muitas tentativas. Aguarde alguns minutos.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// ─── STATUS ─────────────────────────
app.get('/status', (req, res) => {
  res.json({
    status: 'online',
    timestamp: new Date(),
    websocket_clients: clientesWs.size,
  });
});

// ─── FEED GERAL ─────────────────────────
app.get('/feed', autenticarToken, async (req, res) => {
  try {
    const resultado = await pool.query(`
      SELECT 
        clips.nome,
        clips.criado_em,
        clips.cliente_id,
        clips.quadra_id,
        clips.camera_id,
        clientes.nome AS cliente_nome,
        quadras.nome AS quadra_nome
      FROM clips
      INNER JOIN clientes ON clientes.id = clips.cliente_id
      INNER JOIN quadras ON quadras.id = clips.quadra_id
      WHERE clientes.ativo = true
        AND quadras.ativa = true
      ORDER BY clips.criado_em DESC
      LIMIT 50
    `);

    const arquivos = await Promise.all(
      resultado.rows.map(async (clip) => {
        const signedUrl = await getSignedUrl(
          r2,
          new GetObjectCommand({
            Bucket: BUCKET,
            Key: clip.nome,
          }),
          { expiresIn: 3600 }
        );

        return {
          nome: clip.nome,
          url: signedUrl,
          criado: clip.criado_em,
          cliente_id: clip.cliente_id,
          quadra_id: clip.quadra_id,
          camera_id: clip.camera_id,
          cliente_nome: clip.cliente_nome,
          quadra_nome: clip.quadra_nome,
        };
      })
    );

    res.json(arquivos);
  } catch (err) {
    console.error('Erro ao carregar feed:', err);
    res.status(500).json({ erro: 'Erro ao carregar feed' });
  }
});

// ─── LISTAR TODAS AS ARENAS ─────────────────────────
app.get('/clientes', autenticarToken, async (req, res) => {
  try {
    const resultado = await pool.query(`
      SELECT id, nome
      FROM clientes
      WHERE ativo = true
      ORDER BY nome ASC
    `);

    res.json(resultado.rows);
  } catch (err) {
    console.error('Erro ao listar clientes:', err);
    res.status(500).json({ erro: 'Erro ao listar clientes' });
  }
});

// ─── LISTAR QUADRAS DE UMA ARENA ─────────────────────────
app.get('/clientes/:clienteId/quadras', autenticarToken, async (req, res) => {
  try {
    const clienteId = Number(req.params.clienteId);

    if (!clienteId) {
      return res.status(400).json({ erro: 'Arena inválida' });
    }

    const resultado = await pool.query(
      `
      SELECT id, nome, ativa
      FROM quadras
      WHERE cliente_id = $1
        AND ativa = true
      ORDER BY nome ASC
      `,
      [clienteId]
    );

    res.json(resultado.rows);
  } catch (err) {
    console.error('Erro ao listar quadras:', err);
    res.status(500).json({ erro: 'Erro ao listar quadras' });
  }
});

// ─── CLIPES DE UMA QUADRA ─────────────────────────
app.get('/quadras/:quadraId/clips', autenticarToken, async (req, res) => {
  try {
    const quadraId = Number(req.params.quadraId);
    const data = req.query.data;

    if (!quadraId) {
      return res.status(400).json({ erro: 'Quadra inválida' });
    }

    let query = `
      SELECT 
        clips.nome,
        clips.criado_em,
        clips.cliente_id,
        clips.quadra_id,
        clips.camera_id,
        clientes.nome AS cliente_nome,
        quadras.nome AS quadra_nome
      FROM clips
      INNER JOIN clientes ON clientes.id = clips.cliente_id
      INNER JOIN quadras ON quadras.id = clips.quadra_id
      WHERE clips.quadra_id = $1
        AND clientes.ativo = true
        AND quadras.ativa = true
    `;

    const params = [quadraId];

    if (data) {
      query += ` AND DATE(clips.criado_em) = $2`;
      params.push(data);
    }

    query += ` ORDER BY clips.criado_em DESC`;

    const resultado = await pool.query(query, params);

    const arquivos = await Promise.all(
      resultado.rows.map(async (clip) => {
        const signedUrl = await getSignedUrl(
          r2,
          new GetObjectCommand({
            Bucket: BUCKET,
            Key: clip.nome,
          }),
          { expiresIn: 3600 }
        );

        return {
          nome: clip.nome,
          url: signedUrl,
          criado: clip.criado_em,
          cliente_id: clip.cliente_id,
          quadra_id: clip.quadra_id,
          camera_id: clip.camera_id,
          cliente_nome: clip.cliente_nome,
          quadra_nome: clip.quadra_nome,
        };
      })
    );

    res.json(arquivos);
  } catch (err) {
    console.error('Erro ao listar clipes da quadra:', err);
    res.status(500).json({ erro: 'Erro ao listar clipes' });
  }
});

// ─── AUTH: CADASTRO ─────────────────────────
app.post('/auth/cadastro', async (req, res) => {
  try {
    const { nome, email, senha } = req.body;

    if (!nome || !email || !senha) {
      return res.status(400).json({ erro: 'Preencha todos os campos' });
    }

    if (senha.length < 6) {
      return res.status(400).json({ erro: 'A senha deve ter pelo menos 6 caracteres' });
    }

    const existente = await pool.query(
      'SELECT id FROM usuarios WHERE email = $1',
      [email]
    );

    if (existente.rows.length > 0) {
      return res.status(400).json({ erro: 'Email já cadastrado' });
    }

    const hash = await bcrypt.hash(senha, 10);

    await pool.query(
      'INSERT INTO usuarios (nome, email, senha) VALUES ($1, $2, $3)',
      [nome, email, hash]
    );

    const codigo = gerarCodigo();
    const expira = new Date(Date.now() + 15 * 60 * 1000);

    await pool.query(
      'INSERT INTO codigos (email, codigo, tipo, expira_em) VALUES ($1, $2, $3, $4)',
      [email, codigo, 'verificacao', expira]
    );

    await enviarEmail(email, 'Verifique seu email - Highlights', `
      <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; background: #111; color: #fff; padding: 32px; border-radius: 16px;">
        <div style="text-align: center; margin-bottom: 24px;">
          <span style="background: #FFD600; color: #111; padding: 8px 16px; border-radius: 8px; font-weight: bold; font-size: 20px;">▶ Highlights</span>
        </div>
        <h2 style="text-align: center; color: #fff;">Bem-vindo, ${nome}!</h2>
        <p style="color: #888; text-align: center;">Use o código abaixo para verificar seu email:</p>
        <div style="background: #1a1a1a; border: 2px solid #FFD600; border-radius: 12px; padding: 24px; text-align: center; margin: 24px 0;">
          <span style="font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #FFD600;">${codigo}</span>
        </div>
        <p style="color: #555; text-align: center; font-size: 13px;">Este código expira em 15 minutos.</p>
      </div>
    `);

    res.json({ ok: true, mensagem: 'Código enviado para o email' });
  } catch (err) {
    console.error('Erro cadastro:', err);
    res.status(500).json({ erro: 'Erro ao cadastrar' });
  }
});

// ─── AUTH: VERIFICAR EMAIL ─────────────────────────
app.post('/auth/verificar', verifyLimiter, async (req, res) => {
  try {
    const { email, codigo } = req.body;

    const resultado = await pool.query(
      `
      SELECT *
      FROM codigos
      WHERE email = $1
        AND codigo = $2
        AND tipo = 'verificacao'
        AND usado = 0
      ORDER BY id DESC
      LIMIT 1
      `,
      [email, codigo]
    );

    if (resultado.rows.length === 0) {
      return res.status(400).json({ erro: 'Código inválido' });
    }

    const registro = resultado.rows[0];

    if (new Date(registro.expira_em) < new Date()) {
      return res.status(400).json({ erro: 'Código expirado' });
    }

    await pool.query(
      'UPDATE usuarios SET verificado = 1 WHERE email = $1',
      [email]
    );

    await pool.query(
      'UPDATE codigos SET usado = 1 WHERE id = $1',
      [registro.id]
    );

    res.json({ ok: true, mensagem: 'Email verificado com sucesso!' });
  } catch (err) {
    console.error('Erro verificação:', err);
    res.status(500).json({ erro: 'Erro ao verificar' });
  }
});

// ─── AUTH: REENVIAR CÓDIGO ─────────────────────────
app.post('/auth/reenviar', resetLimiter, async (req, res) => {
  try {
    const { email } = req.body;

    const usuario = await pool.query(
      'SELECT * FROM usuarios WHERE email = $1',
      [email]
    );

    if (usuario.rows.length === 0) {
      return res.status(400).json({ erro: 'Email não encontrado' });
    }

    const codigo = gerarCodigo();
    const expira = new Date(Date.now() + 15 * 60 * 1000);

    await pool.query(
      'INSERT INTO codigos (email, codigo, tipo, expira_em) VALUES ($1, $2, $3, $4)',
      [email, codigo, 'verificacao', expira]
    );

    await enviarEmail(email, 'Novo código de verificação - Highlights', `
      <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; background: #111; color: #fff; padding: 32px; border-radius: 16px;">
        <div style="text-align: center; margin-bottom: 24px;">
          <span style="background: #FFD600; color: #111; padding: 8px 16px; border-radius: 8px; font-weight: bold; font-size: 20px;">▶ Highlights</span>
        </div>
        <h2 style="text-align: center; color: #fff;">Novo código de verificação</h2>
        <div style="background: #1a1a1a; border: 2px solid #FFD600; border-radius: 12px; padding: 24px; text-align: center; margin: 24px 0;">
          <span style="font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #FFD600;">${codigo}</span>
        </div>
        <p style="color: #555; text-align: center; font-size: 13px;">Este código expira em 15 minutos.</p>
      </div>
    `);

    res.json({ ok: true });
  } catch (err) {
    console.error('Erro reenvio:', err);
    res.status(500).json({ erro: 'Erro ao reenviar código' });
  }
});

// ─── AUTH: LOGIN ─────────────────────────
app.post('/auth/login', loginLimiter, async (req, res) => {
  try {
    const { email, senha } = req.body;

    const resultado = await pool.query(
      'SELECT * FROM usuarios WHERE email = $1',
      [email]
    );

    if (resultado.rows.length === 0) {
      return res.status(400).json({ erro: 'Email ou senha incorretos' });
    }

    const usuario = resultado.rows[0];

    if (!usuario.verificado) {
      return res.status(400).json({ erro: 'Email não verificado' });
    }

    const senhaCorreta = await bcrypt.compare(senha, usuario.senha);

    if (!senhaCorreta) {
      return res.status(400).json({ erro: 'Email ou senha incorretos' });
    }

    const token = jwt.sign(
      {
        id: usuario.id,
        email: usuario.email,
        nome: usuario.nome,
        role: usuario.role,
      },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      ok: true,
      token,
      usuario: {
        id: usuario.id,
        nome: usuario.nome,
        email: usuario.email,
        role: usuario.role,
      },
    });
  } catch (err) {
    console.error('Erro login:', err);
    res.status(500).json({ erro: 'Erro ao fazer login' });
  }
});

// ─── AUTH: ESQUECI SENHA ─────────────────────────
app.post('/auth/esqueci-senha', resetLimiter, async (req, res) => {
  try {
    const { email } = req.body;

    const resultado = await pool.query(
      'SELECT * FROM usuarios WHERE email = $1',
      [email]
    );

    if (resultado.rows.length === 0) {
      return res.status(400).json({ erro: 'Email não encontrado' });
    }

    const codigo = gerarCodigo();
    const expira = new Date(Date.now() + 15 * 60 * 1000);

    await pool.query(
      'INSERT INTO codigos (email, codigo, tipo, expira_em) VALUES ($1, $2, $3, $4)',
      [email, codigo, 'reset', expira]
    );

    await enviarEmail(email, 'Recuperação de senha - Highlights', `
      <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; background: #111; color: #fff; padding: 32px; border-radius: 16px;">
        <div style="text-align: center; margin-bottom: 24px;">
          <span style="background: #FFD600; color: #111; padding: 8px 16px; border-radius: 8px; font-weight: bold; font-size: 20px;">▶ Highlights</span>
        </div>
        <h2 style="text-align: center; color: #fff;">Recuperação de senha</h2>
        <p style="color: #888; text-align: center;">Use o código abaixo para redefinir sua senha:</p>
        <div style="background: #1a1a1a; border: 2px solid #FFD600; border-radius: 12px; padding: 24px; text-align: center; margin: 24px 0;">
          <span style="font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #FFD600;">${codigo}</span>
        </div>
        <p style="color: #555; text-align: center; font-size: 13px;">Este código expira em 15 minutos.</p>
      </div>
    `);

    res.json({ ok: true });
  } catch (err) {
    console.error('Erro esqueci senha:', err);
    res.status(500).json({ erro: 'Erro ao enviar código' });
  }
});

// ─── AUTH: VERIFICAR RESET ─────────────────────────
app.post('/auth/verificar-reset', verifyLimiter, async (req, res) => {
  try {
    const { email, codigo } = req.body;

    const resultado = await pool.query(
      `
      SELECT *
      FROM codigos
      WHERE email = $1
        AND codigo = $2
        AND tipo = 'reset'
        AND usado = 0
      ORDER BY id DESC
      LIMIT 1
      `,
      [email, codigo]
    );

    if (resultado.rows.length === 0) {
      return res.status(400).json({ erro: 'Código inválido' });
    }

    const registro = resultado.rows[0];

    if (new Date(registro.expira_em) < new Date()) {
      return res.status(400).json({ erro: 'Código expirado' });
    }

    res.json({ ok: true });
  } catch (err) {
    console.error('Erro verificar reset:', err);
    res.status(500).json({ erro: 'Erro ao verificar código' });
  }
});

// ─── AUTH: REDEFINIR SENHA ─────────────────────────
app.post('/auth/redefinir-senha', async (req, res) => {
  try {
    const { email, codigo, novaSenha } = req.body;

    const resultado = await pool.query(
      `
      SELECT *
      FROM codigos
      WHERE email = $1
        AND codigo = $2
        AND tipo = 'reset'
        AND usado = 0
      ORDER BY id DESC
      LIMIT 1
      `,
      [email, codigo]
    );

    if (resultado.rows.length === 0) {
      return res.status(400).json({ erro: 'Código inválido' });
    }

    const registro = resultado.rows[0];

    if (new Date(registro.expira_em) < new Date()) {
      return res.status(400).json({ erro: 'Código expirado' });
    }

    const hash = await bcrypt.hash(novaSenha, 10);

    await pool.query(
      'UPDATE usuarios SET senha = $1 WHERE email = $2',
      [hash, email]
    );

    await pool.query(
      'UPDATE codigos SET usado = 1 WHERE id = $1',
      [registro.id]
    );

    res.json({ ok: true, mensagem: 'Senha redefinida com sucesso!' });
  } catch (err) {
    console.error('Erro redefinir senha:', err);
    res.status(500).json({ erro: 'Erro ao redefinir senha' });
  }
});

// ─── UPLOAD DA CÂMERA ─────────────────────────
app.post('/upload', autenticarCamera, upload.single('file'), async (req, res) => {
  try {
    const file = req.file;

    if (!file) {
      return res.status(400).json({ erro: 'Arquivo não enviado' });
    }

    const ext = path.extname(file.originalname) || '.mp4';
    const nome = `${Date.now()}_${uuidv4()}${ext}`;

    await r2.send(new PutObjectCommand({
      Bucket: BUCKET,
      Key: nome,
      Body: file.buffer,
      ContentType: file.mimetype,
    }));

    await pool.query(
      `
      INSERT INTO clips (nome, cliente_id, quadra_id, camera_id)
      VALUES ($1, $2, $3, $4)
      `,
      [
        nome,
        req.camera.cliente_id,
        req.camera.quadra_id,
        req.camera.id,
      ]
    );

    const signedUrl = await getSignedUrl(
      r2,
      new GetObjectCommand({
        Bucket: BUCKET,
        Key: nome,
      }),
      { expiresIn: 3600 }
    );

    const novoClipe = {
      nome,
      url: signedUrl,
      criado: new Date(),
      cliente_id: req.camera.cliente_id,
      quadra_id: req.camera.quadra_id,
      camera_id: req.camera.id,
    };

    console.log('📥 Upload enviado ao R2:', nome);

    notificarNovoClipe(novoClipe);

    res.json({
      ok: true,
      ...novoClipe,
    });
  } catch (err) {
    console.error('Erro upload:', err);
    res.status(500).json({ erro: 'Erro no upload' });
  }
});

// ─── DOWNLOAD DO CLIPE ─────────────────────────
app.get('/clips/:nome/download', autenticarToken, async (req, res) => {
  try {
    const clip = await pool.query(
      `
      SELECT nome
      FROM clips
      WHERE nome = $1
      LIMIT 1
      `,
      [req.params.nome]
    );

    if (clip.rows.length === 0) {
      return res.status(404).json({ erro: 'Clipe não encontrado' });
    }

    const downloadUrl = await getSignedUrl(
      r2,
      new GetObjectCommand({
        Bucket: BUCKET,
        Key: req.params.nome,
        ResponseContentDisposition: `attachment; filename="${req.params.nome}"`,
        ResponseContentType: 'video/mp4',
      }),
      { expiresIn: 300 }
    );

    res.json({ url: downloadUrl });
  } catch (err) {
    console.error('Erro ao gerar download:', err);
    res.status(500).json({ erro: 'Erro ao gerar download' });
  }
});

// ─── DELETAR CLIPE ─────────────────────────
app.delete('/clips/:nome', autenticarToken, async (req, res) => {
  try {
    const clip = await pool.query(
      `
      SELECT c.nome
      FROM clips c
      INNER JOIN usuarios_clientes uc ON uc.cliente_id = c.cliente_id
      WHERE c.nome = $1
        AND uc.usuario_id = $2
      LIMIT 1
      `,
      [req.params.nome, req.usuario.id]
    );

    if (clip.rows.length === 0) {
      return res.status(404).json({ erro: 'Clipe não encontrado ou sem permissão' });
    }

    await r2.send(new DeleteObjectCommand({
      Bucket: BUCKET,
      Key: req.params.nome,
    }));

    await pool.query(
      'DELETE FROM clips WHERE nome = $1',
      [req.params.nome]
    );

    res.json({ ok: true });
  } catch (err) {
    console.error('Erro ao deletar:', err);
    res.status(500).json({ erro: 'Erro ao deletar' });
  }
});

function autenticarServidor(req, res, next) {
  try {
    const auth = req.headers.authorization;

    if (!auth) {
      return res.status(401).json({
        erro: 'Token não fornecido',
      });
    }

    const token = auth.replace('Bearer ', '');

    req.serverToken = token;

    next();

  } catch (err) {
    console.error(err);

    res.status(401).json({
      erro: 'Token inválido',
    });
  }
}

app.get('/admin/clientes', autenticarToken, autenticarAdmin, async (req, res) => {
  try {
    const resultado = await pool.query(`
      SELECT
        c.id,
        c.nome,
        c.imagem_url,
        c.ativo,
        c.criado_em,
        COUNT(DISTINCT q.id) AS total_quadras,
        COUNT(DISTINCT cam.id) AS total_cameras
      FROM clientes c
      LEFT JOIN quadras q ON q.cliente_id = c.id
      LEFT JOIN cameras cam ON cam.cliente_id = c.id
      GROUP BY c.id
      ORDER BY c.criado_em DESC
    `);

    res.json(resultado.rows);

  } catch (err) {
    console.error(err);
    res.status(500).json({
      erro: 'Erro ao listar clientes'
    });
  }
});

app.post('/admin/clientes', autenticarToken, autenticarAdmin, async (req, res) => {
  try {
    const { nome, imagem_url } = req.body;

    if (!nome) {
      return res.status(400).json({
        erro: 'Nome obrigatório'
      });
    }

    const resultado = await pool.query(
      `
      INSERT INTO clientes (nome, imagem_url)
      VALUES ($1, $2)
      RETURNING *
      `,
      [nome, imagem_url || null]
    );

    res.json({
      ok: true,
      cliente: resultado.rows[0]
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      erro: 'Erro ao criar cliente'
    });
  }
});

app.post('/admin/clientes/:clienteId/quadras', autenticarToken, autenticarAdmin, async (req, res) => {
  try {
    const clienteId = Number(req.params.clienteId);
    const { nome } = req.body;

    const resultado = await pool.query(
      `
      INSERT INTO quadras (cliente_id, nome)
      VALUES ($1, $2)
      RETURNING *
      `,
      [clienteId, nome]
    );

    res.json({
      ok: true,
      quadra: resultado.rows[0]
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      erro: 'Erro ao criar quadra'
    });
  }
});

app.post('/admin/quadras/:quadraId/cameras', autenticarToken, autenticarAdmin, async (req, res) => {
  try {
    const quadraId = Number(req.params.quadraId);
    const { nome } = req.body;

    const quadra = await pool.query(
      `
      SELECT *
      FROM quadras
      WHERE id = $1
      LIMIT 1
      `,
      [quadraId]
    );

    if (quadra.rows.length === 0) {
      return res.status(404).json({
        erro: 'Quadra não encontrada'
      });
    }

    const clienteId = quadra.rows[0].cliente_id;

    const apiKey = `hl_cam_${uuidv4().replace(/-/g, '')}`;
    const idLocal = `cam_${uuidv4().replace(/-/g, '').slice(0, 12)}`;

    const resultado = await pool.query(
      `
      INSERT INTO cameras (
        cliente_id,
        quadra_id,
        nome,
        api_key,
        id_local
      )
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *
      `,
      [
        clienteId,
        quadraId,
        nome,
        apiKey,
        idLocal,
      ]
    );

    res.json({
      ok: true,
      camera: resultado.rows[0]
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      erro: 'Erro ao criar câmera'
    });
  }
});

app.get('/admin/clientes/:clienteId/estrutura', autenticarToken, autenticarAdmin, async (req, res) => {
  try {
    const clienteId = Number(req.params.clienteId);

    const cliente = await pool.query(
      `
      SELECT *
      FROM clientes
      WHERE id = $1
      LIMIT 1
      `,
      [clienteId]
    );

    if (cliente.rows.length === 0) {
      return res.status(404).json({
        erro: 'Cliente não encontrado'
      });
    }

    const quadras = await pool.query(
      `
      SELECT *
      FROM quadras
      WHERE cliente_id = $1
      ORDER BY id ASC
      `,
      [clienteId]
    );

    const cameras = await pool.query(
      `
      SELECT *
      FROM cameras
      WHERE cliente_id = $1
      ORDER BY id ASC
      `,
      [clienteId]
    );

    const servidores = await pool.query(
      `
      SELECT *
      FROM servidores_locais
      WHERE cliente_id = $1
      ORDER BY id ASC
      `,
      [clienteId]
    );

    const licenses = await pool.query(
      `
      SELECT *
      FROM licenses
      WHERE cliente_id = $1
      ORDER BY created_at DESC
      `,
      [clienteId]
    );

    res.json({
      cliente: cliente.rows[0],
      quadras: quadras.rows,
      cameras: cameras.rows,
      servidores: servidores.rows,
      licenses: licenses.rows,
    });



  } catch (err) {
    console.error(err);
    res.status(500).json({
      erro: 'Erro ao carregar estrutura'
    });
  }
});

// ─── ADMIN: REMOVER CAMERA ─────────────────────────
app.delete('/admin/cameras/:id', autenticarToken, autenticarAdmin, async (req, res) => {
  try {
    const cameraId = Number(req.params.id);

    const camera = await pool.query(
      `
      SELECT *
      FROM cameras
      WHERE id = $1
      LIMIT 1
      `,
      [cameraId]
    );

    if (camera.rows.length === 0) {
      return res.status(404).json({
        erro: 'Câmera não encontrada'
      });
    }

    await pool.query(
      `
      DELETE FROM cameras
      WHERE id = $1
      `,
      [cameraId]
    );

    res.json({
      ok: true
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      erro: 'Erro ao remover câmera'
    });
  }
});

// ─── ADMIN: REMOVER QUADRA ─────────────────────────
app.delete('/admin/quadras/:id', autenticarToken, autenticarAdmin, async (req, res) => {
  try {
    const quadraId = Number(req.params.id);

    const cameras = await pool.query(
      `
      SELECT id
      FROM cameras
      WHERE quadra_id = $1
      LIMIT 1
      `,
      [quadraId]
    );

    if (cameras.rows.length > 0) {
      return res.status(400).json({
        erro: 'Não é possível remover a quadra enquanto houver câmeras vinculadas.'
      });
    }

    const resultado = await pool.query(
      `
      DELETE FROM quadras
      WHERE id = $1
      RETURNING *
      `,
      [quadraId]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({
        erro: 'Quadra não encontrada'
      });
    }

    res.json({ ok: true });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      erro: 'Erro ao remover quadra'
    });
  }
});

// ─── ADMIN: REMOVER ARENA ─────────────────────────
app.delete('/admin/clientes/:id', autenticarToken, autenticarAdmin, async (req, res) => {
  try {
    const clienteId = Number(req.params.id);

    const quadras = await pool.query(
      `
      SELECT id
      FROM quadras
      WHERE cliente_id = $1
      LIMIT 1
      `,
      [clienteId]
    );

    if (quadras.rows.length > 0) {
      return res.status(400).json({
        erro: 'Não é possível remover a arena enquanto houver quadras vinculadas.'
      });
    }

    const resultado = await pool.query(
      `
      DELETE FROM clientes
      WHERE id = $1
      RETURNING *
      `,
      [clienteId]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({
        erro: 'Arena não encontrada'
      });
    }

    res.json({ ok: true });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      erro: 'Erro ao remover arena'
    });
  }
});

// ─── ADMIN: CRIAR SERVIDOR LOCAL ─────────────────────────
app.post('/admin/clientes/:clienteId/servidores', autenticarToken, autenticarAdmin, async (req, res) => {
  try {
    const clienteId = Number(req.params.clienteId);
    const { nome } = req.body;

    if (!nome) {
      return res.status(400).json({ erro: 'Nome obrigatório' });
    }

    const token = `hl_srv_${uuidv4().replace(/-/g, '')}`;

    const resultado = await pool.query(
      `
      INSERT INTO servidores_locais (cliente_id, nome, token)
      VALUES ($1, $2, $3)
      RETURNING *
      `,
      [clienteId, nome, token]
    );

    res.json({
      ok: true,
      servidor: resultado.rows[0],
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro ao criar servidor local' });
  }
});

// ─── HEALTH MONITOR ─────────────────────────
app.post('/health/ping', autenticarServidor, async (req, res) => {
  try {
    const token = req.serverToken;

    const {
      cpu_percent,
      ram_percent,
      disco_percent,
      cameras,
    } = req.body;

    const servidor = await pool.query(
      `
      SELECT *
      FROM servidores_locais
      WHERE token = $1
      LIMIT 1
      `,
      [token]
    );

    if (servidor.rows.length === 0) {
      return res.status(404).json({
        erro: 'Servidor não encontrado',
      });
    }

    const servidorId = servidor.rows[0].id;

    await pool.query(
      `
      UPDATE servidores_locais
      SET
        online = true,
        cpu_percent = $1,
        ram_percent = $2,
        disco_percent = $3,
        ultimo_ping = NOW()
      WHERE id = $4
      `,
      [
        cpu_percent,
        ram_percent,
        disco_percent,
        servidorId,
      ]
    );

    if (Array.isArray(cameras)) {
      for (const camera of cameras) {
        await pool.query(
          `
          UPDATE cameras
          SET
            online = $1,
            rtsp_ok = $2,
            replay_ok = $3,
            ultimo_ping = NOW()
          WHERE id_local = $4
          `,
          [
            camera.online,
            camera.rtsp_ok,
            camera.replay_ok,
            camera.camera_id,
          ]
        );
      }
    }

    res.json({
      ok: true,
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      erro: 'Erro no health monitor',
    });
  }
});

app.post('/admin/clientes/:clienteId/licenses', autenticarToken, autenticarAdmin, async (req, res) => {
  try {
    const clienteId = Number(req.params.clienteId);

    const {
      max_quadras = 1,
      max_cameras = 2,
      expires_at = null,
    } = req.body;

    const licenseKey = `HL-LIC-${uuidv4()
      .replace(/-/g, '')
      .toUpperCase()
      .slice(0, 16)}`;

    const resultado = await pool.query(
      `
      INSERT INTO licenses (
        cliente_id,
        license_key,
        max_quadras,
        max_cameras,
        expires_at
      )
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *
      `,
      [
        clienteId,
        licenseKey,
        max_quadras,
        max_cameras,
        expires_at,
      ]
    );

    res.json({
      ok: true,
      license: resultado.rows[0],
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      erro: 'Erro ao criar licença',
    });
  }
});

app.post('/license/validate', async (req, res) => {
  try {
    const {
      license_key,
      hardware_id,
      hostname,
      version,
    } = req.body;

    if (!license_key) {
      return res.status(400).json({
        valid: false,
        erro: 'Licença não informada',
      });
    }

    if (!hardware_id) {
      return res.status(400).json({
        valid: false,
        erro: 'Hardware ID não informado',
      });
    }

    const resultado = await pool.query(
      `
      SELECT
        l.*,
        c.nome AS cliente_nome
      FROM licenses l
      JOIN clientes c ON c.id = l.cliente_id
      WHERE l.license_key = $1
      LIMIT 1
      `,
      [license_key]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({
        valid: false,
        erro: 'Licença não encontrada',
      });
    }

    const license = resultado.rows[0];

    if (license.status !== 'active') {
      return res.status(403).json({
        valid: false,
        erro: 'Licença bloqueada ou inativa',
      });
    }

    if (license.expires_at && new Date(license.expires_at) < new Date()) {
      return res.status(403).json({
        valid: false,
        erro: 'Licença expirada',
      });
    }

    if (!license.hardware_id) {
      await pool.query(
        `
    UPDATE licenses
    SET
      hardware_id = $1,
      activated_at = NOW(),
      last_check_at = NOW()
    WHERE id = $2
    `,
        [hardware_id, license.id]
      );
    } else if (license.hardware_id !== hardware_id) {
      return res.status(403).json({
        valid: false,
        erro: 'Licença já ativada em outro equipamento',
      });
    } else {
      await pool.query(
        `
    UPDATE licenses
    SET last_check_at = NOW()
    WHERE id = $1
    `,
        [license.id]
      );
    }

    res.json({
      valid: true,
      cliente_id: license.cliente_id,
      cliente_nome: license.cliente_nome,
      max_quadras: license.max_quadras,
      max_cameras: license.max_cameras,
      expires_at: license.expires_at,
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      valid: false,
      erro: 'Erro ao validar licença',
    });
  }



});

// ─── START ─────────────────────────
iniciarBanco()
  .then(() => {
    server.listen(PORT, () => {
      console.log(`☁️ Cloud server rodando na porta ${PORT}`);
    });
  })
  .catch((err) => {
    console.error('[DB] Erro ao iniciar banco:', err);
    process.exit(1);
  });