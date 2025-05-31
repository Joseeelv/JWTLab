# JWT Security Lab

A hands-on, intentionally vulnerable Node.js backend designed to demonstrate and exploit common JWT security flaws. This lab is ideal for security professionals, developers, and students interested in web application security.

## Features

- **Multiple JWT Vulnerabilities:**  
  - alg:none Bypass
  - kid Injection
  - Algorithm Confusion
  - Payload Tampering
- **Flag-Based Challenges:**  
  Each successful exploit reveals a unique flag.
- **Easy Setup:**  
  Minimal dependencies and clear instructions.

## Getting Started

### Prerequisites

- **Node.js** (v14 or later)
- **npm** or **yarn**
- **Optional:**  
  - [Burp Suite](https://portswigger.net/burp) for intercepting requests
  - [JWT Editor](https://token.dev/) for modifying tokens

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/Joseeelv/JWTLab.git
cd JWTLab
```
2. **Install Docker:**
- You can download it [here](https://www.docker.com/)

3. **Set environment variables (optional):**
```bash
echo "JWT_SECRET=your_secret_key_here" > .env
```
4. **Start the Docker:**
```bash
docker-compose up --build
```
5. **Access the lab:**
- Connect your own at `http://localhost:8000`

## Lab Structure

- **Registration:** `/register`
- **Login:** `/login`
- **Profile:** `/profile`
- **Admin:** `/admin`

## Example Exploit: alg:none Bypass

1. Log in as a regular use.
2. Capture the JWT using Burp Suite or browser tools.**
3. Modify the token header to `"alg": "none"` and set `"isAdmin": true`.
4. Remove the signature and send the token to `/profile` or `/admin`.
5. Observe admin access and receive the flag: `FLAG{alg_none_bypass}`.

## Acknowledgments

- **OWASP JWT Cheat Sheet** for best practices
- **PortSwigger** for inspiration and tools

---

**Happy hacking!**

