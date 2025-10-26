require('dotenv').config();

function toBool(v, def = false) {
  if (v === undefined) return def;
  return String(v).toLowerCase() === 'true';
}

const dbConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  port: process.env.DB_PORT ? parseInt(process.env.DB_PORT, 10) : 1433, // <— top-level
  database: process.env.DB_NAME,
  options: {
    encrypt: toBool(process.env.DB_ENCRYPT, false),
    trustServerCertificate: toBool(process.env.DB_TRUST_SERVER_CERT, true),
  },
};

module.exports = dbConfig;
