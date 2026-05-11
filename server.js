const express = require('express');
const WebSocket = require('ws');
const http = require('http');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
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
  const mensagem = JSON.stringify({ tipo: 'novo_clipe', clipe });
  clientes.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN) ws.send(mensagem);
  });
}

// ─── MIDDLEWARES ─────────────────────────
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type', 'x-api-key', 'Authorization'],
}));
app.use(express.json());

// ─── BANCO DE DADOS POSTGRESQL ─────────────────────────
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
      nome TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      senha TEXT NOT NULL,
      verificado INTEGER DEFAULT 0,
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
  if (!auth) return res.status(401).json({ erro: 'Token não fornecido' });
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
  limits: { fileSize: 200 * 1024 * 1024 },
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
      return res.status(400).json({ erro: 'Preencha todos os campos' });
    }
    if (senha.length < 6) {
      return res.status(400).json({ erro: 'A senha deve ter pelo menos 6 caracteres' });
    }

    const existente = await pool.query('SELECT id FROM usuarios WHERE email = $1', [email]);
    if (existente.rows.length > 0) {
      return res.status(400).json({ erro: 'Email já cadastrado' });
    }

    const hash = await bcrypt.hash(senha, 10);
    await pool.query('INSERT INTO usuarios (nome, email, senha) VALUES ($1, $2, $3)', [nome, email, hash]);

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
app.post('/auth/verificar', async (req, res) => {
  try {
    const { email, codigo } = req.body;

    const resultado = await pool.query(`
      SELECT * FROM codigos 
      WHERE email = $1 AND codigo = $2 AND tipo = 'verificacao' AND usado = 0
      ORDER BY id DESC LIMIT 1
    `, [email, codigo]);

    if (resultado.rows.length === 0) {
      return res.status(400).json({ erro: 'Código inválido' });
    }

    const registro = resultado.rows[0];
    if (new Date(registro.expira_em) < new Date()) {
      return res.status(400).json({ erro: 'Código expirado' });
    }

    await pool.query('UPDATE usuarios SET verificado = 1 WHERE email = $1', [email]);
    await pool.query('UPDATE codigos SET usado = 1 WHERE id = $1', [registro.id]);

    res.json({ ok: true, mensagem: 'Email verificado com sucesso!' });
  } catch (err) {
    console.error('Erro verificação:', err);
    res.status(500).json({ erro: 'Erro ao verificar' });
  }
});

// ─── AUTH: REENVIAR CÓDIGO ─────────────────────────
app.post('/auth/reenviar', async (req, res) => {
  try {
    const { email } = req.body;

    const usuario = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
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
app.post('/auth/login', async (req, res) => {
  try {
    const { email, senha } = req.body;

    const resultado = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
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
      { id: usuario.id, email: usuario.email, nome: usuario.nome },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      ok: true,
      token,
      usuario: { id: usuario.id, nome: usuario.nome, email: usuario.email },
    });
  } catch (err) {
    console.error('Erro login:', err);
    res.status(500).json({ erro: 'Erro ao fazer login' });
  }
});

// ─── AUTH: ESQUECI SENHA ─────────────────────────
app.post('/auth/esqueci-senha', async (req, res) => {
  try {
    const { email } = req.body;

    const resultado = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
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
app.post('/auth/verificar-reset', async (req, res) => {
  try {
    const { email, codigo } = req.body;

    const resultado = await pool.query(`
      SELECT * FROM codigos 
      WHERE email = $1 AND codigo = $2 AND tipo = 'reset' AND usado = 0
      ORDER BY id DESC LIMIT 1
    `, [email, codigo]);

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

    const resultado = await pool.query(`
      SELECT * FROM codigos 
      WHERE email = $1 AND codigo = $2 AND tipo = 'reset' AND usado = 0
      ORDER BY id DESC LIMIT 1
    `, [email, codigo]);

    if (resultado.rows.length === 0) {
      return res.status(400).json({ erro: 'Código inválido' });
    }

    const registro = resultado.rows[0];
    if (new Date(registro.expira_em) < new Date()) {
      return res.status(400).json({ erro: 'Código expirado' });
    }

    const hash = await bcrypt.hash(novaSenha, 10);
    await pool.query('UPDATE usuarios SET senha = $1 WHERE email = $2', [hash, email]);
    await pool.query('UPDATE codigos SET usado = 1 WHERE id = $1', [registro.id]);

    res.json({ ok: true, mensagem: 'Senha redefinida com sucesso!' });
  } catch (err) {
    console.error('Erro redefinir senha:', err);
    res.status(500).json({ erro: 'Erro ao redefinir senha' });
  }
});

// ─── UPLOAD ─────────────────────────
app.post('/upload', autenticar, upload.single('file'), async (req, res) => {
  try {
    const file = req.file;
    const cameraId = req.body.camera_id;

    if (!file) {
      return res.status(400).json({ erro: 'Arquivo não enviado' });
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
    notificarNovoClipe(novoClipe);

    res.json({ ok: true, ...novoClipe });
  } catch (err) {
    console.error('Erro upload:', err);
    res.status(500).json({ erro: 'Erro no upload' });
  }
});

// ─── LISTAR CLIPES ─────────────────────────
app.get('/clips', autenticarToken, async (req, res) => {
  try {
    let arquivos = [];
    let continuationToken = undefined;

    do {
      const data = await r2.send(new ListObjectsV2Command({
        Bucket: BUCKET,
        ContinuationToken: continuationToken,
      }));

      const pagina = (data.Contents || [])
        .filter(f => f.Key.endsWith('.mp4'))
        .map(f => ({
          nome: f.Key,
          url: `${process.env.R2_PUBLIC_URL}/${f.Key}`,
          tamanho: f.Size,
          criado: f.LastModified,
        }));

      arquivos = arquivos.concat(pagina);
      continuationToken = data.IsTruncated ? data.NextContinuationToken : undefined;

    } while (continuationToken);

    arquivos.sort((a, b) => new Date(b.criado) - new Date(a.criado));
    res.json(arquivos);
  } catch (err) {
    console.error('Erro ao listar:', err);
    res.status(500).json({ erro: 'Erro ao listar clipes' });
  }
});

// ─── DELETAR CLIPE ─────────────────────────
app.delete('/clips/:nome', autenticarToken, async (req, res) => {
  try {
    await r2.send(new DeleteObjectCommand({
      Bucket: BUCKET,
      Key: req.params.nome,
    }));
    res.json({ ok: true });
  } catch (err) {
    console.error('Erro ao deletar:', err);
    res.status(500).json({ erro: 'Erro ao deletar' });
  }
});

// ─── URL ASSINADA ─────────────────────────
app.get('/clips/:nome/signed', autenticarToken, async (req, res) => {
  try {
    const url = await getSignedUrl(
      r2,
      new GetObjectCommand({ Bucket: BUCKET, Key: req.params.nome }),
      { expiresIn: 3600 }
    );
    res.json({ url });
  } catch (err) {
    console.error('Erro ao gerar URL:', err);
    res.status(500).json({ erro: 'Erro ao gerar URL assinada' });
  }
});

// ─── START ─────────────────────────
iniciarBanco().then(() => {
  server.listen(PORT, () => {
    console.log(`☁️ Cloud server rodando na porta ${PORT}`);
  });
}).catch(err => {
  console.error('[DB] Erro ao iniciar banco:', err);
  process.exit(1);
});