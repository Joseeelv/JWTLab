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
git clone https://github.com/yourusername/jwt-security-lab.git
cd jwt-security-lab
```
2. **Install dependencies:**
```bash
mpm install
```

3. **Set environment variables (optional):**
```bash
echo "JWT_SECRET=your_secret_key_here" > .env
```
4. **Start the server:**
```bash
npm start
```
5. **Access the lab:**
- **Backend:** `http://localhost:3000`
- **Recommended Frontend:** Use the provided frontend or connect your own at `http://localhost:8000`

## Lab Structure

- **Registration:** `/register`
- **Login:** `/login`
- **Profile:** `/profile`
- **Admin:** `/admin`

## Exploitation Guide

Refer to the [blog post](#) or the project documentation for step-by-step instructions on exploiting each vulnerability.

## Example Exploit: alg:none Bypass

1. **Log in as a regular user.**
2. **Capture the JWT using Burp Suite or browser tools.**
3. **Modify the token header to `"alg": "none"` and set `"isAdmin": true`.**
4. **Remove the signature and send the token to `/profile` or `/admin`.**
5. **Observe admin access and receive the flag: `FLAG{alg_none_bypass}`.**

## Acknowledgments

- **OWASP JWT Cheat Sheet** for best practices
- **PortSwigger** for inspiration and tools

---

**Happy hacking!**

