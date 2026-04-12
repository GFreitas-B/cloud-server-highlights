const express = require('express');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json());

const pastaUploads = path.join(__dirname, 'uploads');

if (!fs.existsSync(pastaUploads)) {
  fs.mkdirSync(pastaUploads, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, pastaUploads);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const nome = `${Date.now()}_${uuidv4()}${ext}`;
    cb(null, nome);
  }
});

const upload = multer({ storage });

app.use('/videos', express.static(pastaUploads));

// STATUS
app.get('/status', (req, res) => {
  res.json({
    status: 'online',
    timestamp: new Date()
  });
});

// UPLOAD
app.post('/upload', upload.single('file'), (req, res) => {
  try {
    const file = req.file;
    const cameraId = req.body.camera_id;

    if (!file) {
      return res.status(400).json({ erro: 'Arquivo não enviado' });
    }

    const url = `${req.protocol}://${req.get('host')}/videos/${file.filename}`;

    console.log('📥 Upload recebido:', file.filename);

    res.json({
      ok: true,
      url,
      nome: file.filename,
      camera_id: cameraId
    });

  } catch (err) {
    console.error('Erro upload:', err);
    res.status(500).json({ erro: 'Erro no upload' });
  }
});

// LISTAR CLIPES
app.get('/clips', (req, res) => {
  const arquivos = fs.readdirSync(pastaUploads)
    .filter(f => f.endsWith('.mp4'))
    .map(f => {
      const full = path.join(pastaUploads, f);
      const stats = fs.statSync(full);

      return {
        nome: f,
        url: `${req.protocol}://${req.get('host')}/videos/${f}`,
        tamanho: stats.size,
        criado: stats.mtime
      };
    })
    .sort((a, b) => b.criado - a.criado);

  res.json(arquivos);
});

app.listen(PORT, () => {
  console.log(`☁️ Cloud server rodando em http://localhost:${PORT}`);
});