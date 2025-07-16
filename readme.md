# 💥 PyBlast - The Ultimate Hash Cracking Engine

&#x20;&#x20;

> **PyBlast** is a high-performance, multi-threaded, auto-detecting hash cracker for Linux systems. It supports both CPU and GPU cracking with advanced features like resume, salt support, and progress monitoring. Built for hackers and cybersecurity researchers.

---

## 🚀 Features

- 🔍 **Auto-detect hash type** (md5, sha1, sha256, sha512, ntlm, bcrypt, etc)
- 🎮 **Multi-threaded** password cracking (CPU)
- ⚡ **Hashcat GPU Mode** for blazingly fast brute-force
- 🧠 **Resume** from the last attempted password
- 📦 **Save cracked passwords** to `cracked.txt`
- 🔥 **Live system stats**: CPU, RAM, GPU usage
- 🌈 **Rich colored terminal output** with `rich` and `tqdm`
- 🧂 **Salted hash** cracking support

---

## 📸 Screenshot

```
System Information
• OS: Linux-Windows-WSL2
• CPU: AMD Ryzen / Intel (8 cores, 16 threads)
• RAM: 7.9 GB
• GPU(s): NVIDIA RTX 4060

🔥 Cracking Progress: 48% ▓▓▓▓▓▓▓▓▓░░░░░░░░░  7,245,122 / 14,344,373
✓ MATCH: 'i love u' → 157d7e5dd205abedbe8...
✅ Cracking complete!
```

---

## 📦 Installation

```bash
sudo apt update && sudo apt install python3-pip hashcat
pip3 install -r requirements.txt
```

**Dependencies:**

- `tqdm`
- `rich`
- `psutil`
- `GPUtil`

```bash
pip3 install tqdm rich psutil GPUtil
```

---

## 🧠 Usage

```bash
python3 super_cracker.py --wordlist rockyou.txt --hashes hashes.txt --threads 20 --type sha256
```

### 💣 GPU Mode (Hashcat Required)

```bash
python3 super_cracker.py --wordlist rockyou.txt --hashes hashes.txt --gpu
```

### 🛠 Flags

| Option       | Description                              |
| ------------ | ---------------------------------------- |
| `--wordlist` | Path to password list (e.g. rockyou.txt) |
| `--hashes`   | File with hashes (one per line)          |
| `--type`     | (Optional) Hash type to use              |
| `--threads`  | Number of CPU threads                    |
| `--resume`   | Resume from last saved position          |
| `--gpu`      | Use Hashcat for GPU cracking             |
| `--salt`     | Add salt to passwords                    |

---

## 🧪 Supported Hash Types

- MD5
- SHA1
- SHA256
- SHA512
- NTLM
- Bcrypt (GPU only)

---

## ✨ Credit

Made with 💻 by [@kishwordulal1234](https://github.com/kishwordulal1234)

Star ⭐ the repo if you liked it!

---

📁 Example Files
```bash
echo -n "i love u" | sha256sum | cut -d ' ' -f1 > hashes.txt
echo "i love u" > test.txt


python3 super_cracker.py --wordlist test.txt --hashes hashes.txt --type sha256 --threads 5
```
## 🔐 Disclaimer

> For educational purposes only. Use responsibly and legally.

