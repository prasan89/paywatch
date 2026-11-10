import { createServer } from 'http'
import { readFileSync, existsSync } from 'fs'
import { join, extname, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const dist = join(__dirname, 'dist')
const PORT = process.env.PORT || 3000

const mime = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.css': 'text/css',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.json': 'application/json',
  '.woff2': 'font/woff2',
}

createServer((req, res) => {
  const url = req.url.split('?')[0]
  let filePath = join(dist, url === '/' ? 'index.html' : url)
  if (!existsSync(filePath)) filePath = join(dist, 'index.html')
  try {
    const ext = extname(filePath)
    res.setHeader('Content-Type', mime[ext] || 'application/octet-stream')
    res.setHeader('Cache-Control', ext === '.html' ? 'no-cache' : 'max-age=31536000')
    res.end(readFileSync(filePath))
  } catch {
    res.writeHead(404)
    res.end('Not found')
  }
}).listen(PORT, '0.0.0.0', () => console.log(`Serving dist from ${dist} on port ${PORT}`))
