const express = require('express');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const { S3Client, PutObjectCommand, ListObjectsV2Command, GetObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json());

// R2 Client
const r2 = new S3Client({
  region: 'auto',
  endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: process.env.R2_ACCESS_KEY_ID,
    secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
  },
});

const BUCKET = process.env.R2_BUCKET_NAME;

// Multer em memória (sem salvar em disco)
const upload = multer({ storage: multer.memoryStorage() });

// STATUS
app.get('/status', (req, res) => {
  res.json({ status: 'online', timestamp: new Date() });
});

// UPLOAD
app.post('/upload', upload.single('file'), async (req, res) => {
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

    // URL pública (requer domínio público ativado no R2)
    const url = `${process.env.R2_PUBLIC_URL}/${nome}`;

    console.log('📥 Upload enviado ao R2:', nome);

    res.json({ ok: true, url, nome, camera_id: cameraId });

  } catch (err) {
    console.error('Erro upload:', err);
    res.status(500).json({ erro: 'Erro no upload' });
  }
});

// LISTAR CLIPES
app.get('/clips', async (req, res) => {
  try {
    const data = await r2.send(new ListObjectsV2Command({ Bucket: BUCKET }));

    const arquivos = (data.Contents || [])
      .filter(f => f.Key.endsWith('.mp4'))
      .map(f => ({
        nome: f.Key,
        url: `${process.env.R2_PUBLIC_URL}/${f.Key}`,
        tamanho: f.Size,
        criado: f.LastModified,
      }))
      .sort((a, b) => new Date(b.criado) - new Date(a.criado));

    res.json(arquivos);
  } catch (err) {
    console.error('Erro ao listar:', err);
    res.status(500).json({ erro: 'Erro ao listar clipes' });
  }
});

// DELETAR CLIPE
app.delete('/clips/:nome', async (req, res) => {
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

// URL ASSINADA (acesso temporário sem URL pública)
app.get('/clips/:nome/signed', async (req, res) => {
  try {
    const url = await getSignedUrl(
      r2,
      new GetObjectCommand({ Bucket: BUCKET, Key: req.params.nome }),
      { expiresIn: 3600 } // 1 hora
    );

    res.json({ url });
  } catch (err) {
    console.error('Erro ao gerar URL:', err);
    res.status(500).json({ erro: 'Erro ao gerar URL assinada' });
  }
});

app.listen(PORT, () => {
  console.log(`☁️ Cloud server rodando em http://localhost:${PORT}`);
});
