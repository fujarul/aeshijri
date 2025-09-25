<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>AES-128 Encryption Demo</title>
  <style>
    body {
      margin: 0;
      padding: 0;
      font-family: Arial, sans-serif;
      background: linear-gradient(135deg, #667eea, #764ba2);
      display: flex;
      align-items: center;
      justify-content: center;
      height: 100vh;
    }
    .container {
      background: #fff;
      padding: 30px;
      border-radius: 20px;
      box-shadow: 0 8px 20px rgba(0,0,0,0.3);
      width: 600px;
      max-width: 90%;
    }
    h1 {
      text-align: center;
      color: #333;
      margin-bottom: 20px;
    }
    label {
      font-weight: bold;
      margin-top: 12px;
      display: block;
      text-align: left;
    }
    input, textarea {
      width: 100%;
      padding: 10px;
      margin-top: 6px;
      border: 1px solid #ccc;
      border-radius: 8px;
      font-size: 14px;
    }
    textarea {
      resize: vertical;
    }
    .btn-group {
      display: flex;
      justify-content: space-between;
      margin-top: 20px;
    }
    button {
      flex: 1;
      margin: 0 5px;
      padding: 12px;
      font-size: 15px;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      background: #667eea;
      color: #fff;
      transition: 0.3s;
    }
    button:hover {
      background: #764ba2;
    }
    .output {
      margin-top: 15px;
      background: #f9f9f9;
      padding: 10px;
      border-radius: 8px;
      font-family: monospace;
      min-height: 40px;
      word-wrap: break-word;
      text-align: left;
    }
  </style>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script>
</head>
<body>
  <div class="container">
    <h1>AES-128 Encryption</h1>

    <label for="key">Key (16 karakter):</label>
    <input type="text" id="key" value="abcdefghijklmnop">

    <label for="iv">IV (16 karakter):</label>
    <input type="text" id="iv" value="1234567890abcdef">

    <label for="plaintext">Plaintext:</label>
    <textarea id="plaintext" rows="3">This is 16 bytes</textarea>

    <div class="btn-group">
      <button onclick="encrypt()">Enkripsi</button>
      <button onclick="decrypt()">Dekripsi</button>
    </div>

    <label for="ciphertext">Ciphertext (Base64):</label>
    <div class="output" id="ciphertext"></div>

    <label for="decrypted">Hasil Dekripsi:</label>
    <div class="output" id="decrypted"></div>
  </div>

  <script>
    function encrypt() {
      const keyInput = document.getElementById("key").value;
      const ivInput = document.getElementById("iv").value;
      const plaintext = document.getElementById("plaintext").value;

      if (keyInput.length !== 16 || ivInput.length !== 16) {
        alert("Key dan IV harus 16 karakter (128 bit).");
        return;
      }

      const key = CryptoJS.enc.Utf8.parse(keyInput);
      const iv = CryptoJS.enc.Utf8.parse(ivInput);

      const encrypted = CryptoJS.AES.encrypt(plaintext, key, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      });

      document.getElementById("ciphertext").innerText = encrypted.toString();
    }

    function decrypt() {
      const keyInput = document.getElementById("key").value;
      const ivInput = document.getElementById("iv").value;
      const ciphertext = document.getElementById("ciphertext").innerText;

      if (!ciphertext) {
        alert("Belum ada ciphertext, silakan enkripsi dulu.");
        return;
      }

      const key = CryptoJS.enc.Utf8.parse(keyInput);
      const iv = CryptoJS.enc.Utf8.parse(ivInput);

      const decrypted = CryptoJS.AES.decrypt(ciphertext, key, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      });

      document.getElementById("decrypted").innerText = decrypted.toString(CryptoJS.enc.Utf8);
    }
  </script>
</body>
</html>
