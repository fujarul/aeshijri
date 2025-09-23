<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>AES Crypto App</title>
  <style>
    :root{--bg:#0f172a;--card:#111827;--accent:#06b6d4;--muted:#9ca3af;--glass:rgba(255,255,255,0.03)}
    html,body{height:100%;margin:0;font-family:Inter,system-ui,Segoe UI,Roboto,'Noto Sans',sans-serif;background:linear-gradient(180deg,#071024 0%, #04122a 100%);color:#e6eef8}
    .wrap{max-width:900px;margin:40px auto;padding:28px;background:linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0.01));border-radius:12px;box-shadow:0 8px 30px rgba(2,6,23,0.6)}
    h1{margin:0 0 8px;font-size:20px}
    p.lead{margin:0 0 18px;color:var(--muted)}
    .grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
    .card{background:var(--card);padding:14px;border-radius:10px;box-shadow:inset 0 1px 0 rgba(255,255,255,0.02)}
    label{display:block;font-size:13px;color:var(--muted);margin-bottom:6px}
    input[type=text],input[type=password],textarea,select{width:100%;padding:10px;border-radius:8px;border:1px solid rgba(255,255,255,0.04);background:var(--glass);color:inherit;resize:vertical}
    textarea{min-height:120px}
    .row{display:flex;gap:8px}
    button{background:var(--accent);border:none;padding:10px 12px;border-radius:8px;color:#012;cursor:pointer;font-weight:600}
    .muted{color:var(--muted);font-size:13px}
    .result{word-break:break-all;background:rgba(0,0,0,0.2);padding:10px;border-radius:8px;margin-top:8px}
    .full{grid-column:1/-1}
    footer{margin-top:12px;color:var(--muted);font-size:13px}
    .small{font-size:12px}
    @media (max-width:720px){.grid{grid-template-columns:1fr}}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>AES-GCM Web Crypto — Aplikasi Kriptografi</h1>
    <p class="lead">Encrypt & decrypt text menggunakan AES-GCM di browser. Kunci diturunkan dari password lewat PBKDF2 (secure default). Tidak ada data yang dikirim ke server — semua berjalan di browser.</p>

    <div class="grid">
      <div class="card">
        <label for="plaintext">Plaintext (pesan)</label>
        <textarea id="plaintext" placeholder="Tulis pesan yang ingin dienkripsi..."></textarea>

        <label for="password">Password</label>
        <input id="password" type="password" placeholder="Password untuk derive key" />

        <label for="iterations">PBKDF2 Iterations</label>
        <select id="iterations">
          <option value="100000">100,000 (default)</option>
          <option value="200000">200,000</option>
          <option value="500000">500,000</option>
        </select>

        <div style="margin-top:10px;display:flex;gap:8px">
          <button id="encryptBtn">Encrypt</button>
          <button id="downloadEncBtn" disabled>Download Encrypted</button>
        </div>

        <div class="muted small" style="margin-top:10px">Output (base64):</div>
        <div id="encOutput" class="result">-</div>
      </div>

      <div class="card">
        <label for="encInput">Encrypted (paste base64 here)</label>
        <textarea id="encInput" placeholder="Tempel data enkripsi di sini (base64)"></textarea>

        <label for="decPassword">Password untuk Decrypt</label>
        <input id="decPassword" type="password" placeholder="Masukkan password yang sama" />

        <div style="margin-top:10px;display:flex;gap:8px">
          <button id="decryptBtn">Decrypt</button>
          <input id="fileEnc" type="file" accept="*/*" />
        </div>

        <div class="muted small" style="margin-top:10px">Decrypted text:</div>
        <div id="decOutput" class="result">-</div>
      </div>

      <div class="card full">
        <h3 style="margin-top:0">Penjelasan teknis singkat</h3>
        <ul class="muted small">
          <li>Kunci AES-256-GCM diturunkan dari password menggunakan PBKDF2 dengan SHA-256 dan salt acak.</li>
          <li>IV (nonce) 12-byte acak untuk AES-GCM.</li>
          <li>Format output: base64( salt || iv || ciphertext ). Saat decrypt, fungsi mem-parsing ketiga bagian ini.</li>
          <li>Semua operasi menggunakan Web Crypto API — tidak meninggalkan browser.</li>
        </ul>
        <h4>Cara kerja algoritma:</h4>
        <ol class="muted small">
          <li><b>Input:</b> User memasukkan pesan (plaintext) + password.</li>
          <li><b>Salt:</b> Program membuat salt acak 16 byte. Salt ini mencegah serangan kamus (dictionary attack).</li>
          <li><b>PBKDF2:</b> Password + salt diproses dengan fungsi <i>key derivation</i> PBKDF2 (SHA-256, ribuan iterasi) → menghasilkan kunci 256 bit.</li>
          <li><b>IV:</b> Program membuat IV (Initialization Vector) 12 byte acak untuk setiap enkripsi. IV harus unik agar aman.</li>
          <li><b>Enkripsi AES-GCM:</b> Plaintext dienkripsi dengan kunci + IV menggunakan mode GCM (Galois/Counter Mode) → menghasilkan ciphertext + authentication tag.</li>
          <li><b>Keluaran:</b> Salt + IV + ciphertext digabung, lalu dikodekan base64. Inilah yang ditampilkan/didownload.</li>
          <li><b>Dekripsi:</b> Data base64 dibagi lagi (salt, IV, ciphertext), password diproses ulang dengan salt yang sama untuk menghasilkan kunci yang identik, lalu AES-GCM decrypt mengembalikan plaintext.</li>
        </ol>
      </div>

    </div>

    <footer>Built with Web Crypto API — AES-GCM + PBKDF2. Safe for learning & small use cases.</footer>
  </div>

  <script>
    // Utility helpers
    const bufToBase64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
    const base64ToBuf = (b64) => Uint8Array.from(atob(b64), c=>c.charCodeAt(0));

    async function deriveKey(password, salt, iterations=100000) {
      const enc = new TextEncoder();
      const baseKey = await crypto.subtle.importKey(
        'raw', enc.encode(password), {name:'PBKDF2'}, false, ['deriveKey']
      );
      return crypto.subtle.deriveKey(
        {name:'PBKDF2', salt, iterations: Number(iterations), hash:'SHA-256'},
        baseKey,
        {name:'AES-GCM', length:256},
        false,
        ['encrypt','decrypt']
      );
    }

    async function encryptText(plaintext, password, iterations=100000) {
      const enc = new TextEncoder();
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const key = await deriveKey(password, salt, iterations);
      const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, enc.encode(plaintext));
      // concat salt + iv + ciphertext
      const combined = new Uint8Array(salt.byteLength + iv.byteLength + ct.byteLength);
      combined.set(salt, 0);
      combined.set(iv, salt.byteLength);
      combined.set(new Uint8Array(ct), salt.byteLength + iv.byteLength);
      return bufToBase64(combined.buffer);
    }

    async function decryptText(base64data, password, iterations=100000) {
      const combined = base64ToBuf(base64data);
      if (combined.length < 16 + 12 + 16) throw new Error('Data enkripsi tidak valid atau terlalu pendek');
      const salt = combined.slice(0,16);
      const iv = combined.slice(16, 28);
      const ct = combined.slice(28);
      const key = await deriveKey(password, salt, iterations);
      const plainBuf = await crypto.subtle.decrypt({name:'AES-GCM', iv}, key, ct);
      return new TextDecoder().decode(plainBuf);
    }

    // UI bindings
    const encryptBtn = document.getElementById('encryptBtn');
    const decryptBtn = document.getElementById('decryptBtn');
    const plaintextEl = document.getElementById('plaintext');
    const passwordEl = document.getElementById('password');
    const iterationsEl = document.getElementById('iterations');
    const encOutput = document.getElementById('encOutput');
    const encInput = document.getElementById('encInput');
    const decPassword = document.getElementById('decPassword');
    const decOutput = document.getElementById('decOutput');
    const downloadEncBtn = document.getElementById('downloadEncBtn');
    const fileEnc = document.getElementById('fileEnc');

    encryptBtn.addEventListener('click', async ()=>{
      try{
        const text = plaintextEl.value;
        if(!text) return alert('Masukkan plaintext terlebih dahulu');
        const pwd = passwordEl.value;
        if(!pwd) return alert('Masukkan password');
        encryptBtn.disabled = true;
        encryptBtn.textContent = 'Encrypting...';
        const base64 = await encryptText(text, pwd, iterationsEl.value);
        encOutput.textContent = base64;
        encInput.value = base64;
        downloadEncBtn.disabled = false;
      }catch(e){
        console.error(e);
        alert('Gagal enkripsi: '+ e.message);
      }finally{
        encryptBtn.disabled = false;
        encryptBtn.textContent = 'Encrypt';
      }
    });

    decryptBtn.addEventListener('click', async ()=>{
      try{
        const data = encInput.value.trim();
        if(!data) return alert('Masukkan data enkripsi (base64)');
        const pwd = decPassword.value;
        if(!pwd) return alert('Masukkan password untuk dekripsi');
        decryptBtn.disabled = true;
        decryptBtn.textContent = 'Decrypting...';
        const plain = await decryptText(data, pwd, iterationsEl.value);
        decOutput.textContent = plain;
      }catch(e){
        console.error(e);
        alert('Gagal dekripsi: ' + e.message);
      }finally{
        decryptBtn.disabled = false;
        decryptBtn.textContent = 'Decrypt';
      }
    });

    // allow downloading encrypted payload as .bin
    downloadEncBtn.addEventListener('click', ()=>{
      const data = encOutput.textContent.trim();
      if(!data) return;
      const blob = new Blob([data], {type:'text/plain'});
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = 'encrypted.txt';
      document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    });

    // allow user to select file containing base64 encrypted string
    fileEnc.addEventListener('change', async (e)=>{
      const f = e.target.files[0];
      if(!f) return;
      const txt = await f.text();
      encInput.value = txt.trim();
      // optionally auto-decrypt if password provided
    });

  </script>
</body>
</html>
