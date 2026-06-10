/**
 * ============================================================
 * intelli-dns — Script de Carga Masiva de Whitelist a Redis
 * Lee el archivo tranco_top1m_domains.csv línea por línea
 * y guarda los dominios en lotes de 10,000 usando SADD.
 *
 * Requiere un archivo .env en esta misma carpeta con:
 *   REDIS_HOST, REDIS_PORT, REDIS_PASSWORD
 * ============================================================
 */

const fs = require('fs');
const readline = require('readline');
const path = require('path');
const Redis = require('ioredis');
require('dotenv').config({ path: path.join(__dirname, '.env.example') });

// Variables leídas del .env (sin valores hardcodeados)
const REDIS_HOST = process.env.REDIS_HOST;
const REDIS_PORT = process.env.REDIS_PORT;
const REDIS_PASSWORD = process.env.REDIS_PASSWORD;

if (!REDIS_HOST || !REDIS_PORT || !REDIS_PASSWORD) {
  console.error('Error: Faltan variables de entorno. Crea un archivo .env con REDIS_HOST, REDIS_PORT y REDIS_PASSWORD.');
  process.exit(1);
}

const redisClient = new Redis({
  host: REDIS_HOST,
  port: REDIS_PORT,
  password: REDIS_PASSWORD,
  maxRetriesPerRequest: 3,
  connectTimeout: 5000
});

const CSV_FILE = path.join(__dirname, './data/tranco_top1m_domains.csv');
const BATCH_SIZE = 10000; // Tamaño de lote para multiprocesamiento
const KEY_NAME = 'whitelist:domains';

async function loadWhitelist() {
  console.log('Iniciando carga masiva de dominios conocidos a Redis...');
  
  if (!fs.existsSync(CSV_FILE)) {
    console.error(`Error: El archivo ${CSV_FILE} no existe en la carpeta.`);
    redisClient.disconnect();
    process.exit(1);
  }

  // Esperar a que la conexión esté lista o falle por timeout
  console.log('Conectando a Redis...');
  let useMock = false;
  const mockSet = new Set();

  try {
    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Tiempo de espera de conexión agotado (timeout)'));
      }, 2000);

      redisClient.once('ready', () => {
        clearTimeout(timeout);
        resolve();
      });

      redisClient.once('error', (err) => {
        clearTimeout(timeout);
        reject(err);
      });
    });
    console.log('Conexión a Redis lista. Leyendo y procesando CSV...');
  } catch (err) {
    console.log('\n[INFO] Redis no está activo localmente.');
    console.log('Activando MODO SIMULACIÓN en memoria para probar la lectura y parseo del CSV en Windows sin Redis.');
    useMock = true;
  }

  const fileStream = fs.createReadStream(CSV_FILE);
  const rl = readline.createInterface({
    input: fileStream,
    crlfDelay: Infinity
  });

  const startTime = Date.now();
  let count = 0;
  let batch = [];

  for await (const line of rl) {
    if (!line) continue;
    
    // El CSV está en formato: rank,domain (ej: 1,google.com)
    const parts = line.split(',');
    if (parts.length >= 2) {
      const domain = parts[1].trim().toLowerCase();
      if (domain) {
        batch.push(domain);
        count++;
      }
    }

    // Si llenamos el tamaño del lote, lo enviamos
    if (batch.length >= BATCH_SIZE) {
      const currentBatch = batch;
      batch = []; // Limpiar para el siguiente lote
      
      if (useMock) {
        // En simulación, guardamos en el Set de Javascript local
        currentBatch.forEach(d => mockSet.add(d));
      } else {
        await redisClient.sadd(KEY_NAME, ...currentBatch);
      }
      
      // Imprimir progreso cada 100k dominios
      if (count % 100000 === 0) {
        console.log(`Procesados ${count.toLocaleString()} de 1,000,000 dominios...`);
      }
    }
  }

  // Enviar cualquier dominio sobrante en el último lote
  if (batch.length > 0) {
    if (useMock) {
      batch.forEach(d => mockSet.add(d));
    } else {
      await redisClient.sadd(KEY_NAME, ...batch);
    }
  }

  const duration = ((Date.now() - startTime) / 1000).toFixed(2);
  console.log(`\n¡Carga masiva completada con éxito!`);
  console.log(`Total de dominios procesados: ${count.toLocaleString()}`);
  console.log(`Tiempo transcurrido: ${duration} segundos`);
  if (useMock) {
    console.log(`Guardado en Set de simulación en memoria JS (Tamaño final: ${mockSet.size.toLocaleString()} elementos únicos)`);
  } else {
    console.log(`Guardado en el Set de Redis: "${KEY_NAME}"`);
  }

  redisClient.disconnect();
}

loadWhitelist().catch(err => {
  console.error('\nError durante el proceso de carga:', err.message);
  if (redisClient) {
    redisClient.disconnect();
  }
});
