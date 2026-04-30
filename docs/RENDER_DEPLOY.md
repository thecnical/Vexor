# Backend Deploy on Render (Free)

## Step 1: Push to GitHub

Make sure your code is on GitHub first.

## Step 2: Create Render Account

Go to [render.com](https://render.com) and sign up (free).

## Step 3: New Web Service

1. Click **New** → **Web Service**
2. Connect your GitHub repo
3. Select the `vexor` repo
4. Configure:

```
Name:        vexor-backend
Root Dir:    backend
Runtime:     Python 3
Build Cmd:   pip install -r requirements.txt
Start Cmd:   uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

## Step 4: Environment Variables

In Render dashboard → Environment:

```
SECRET_KEY          = (generate random: python3 -c "import secrets; print(secrets.token_hex(32))")
GROQ_API_KEY        = (from console.groq.com — free)
NVIDIA_API_KEY      = (from build.nvidia.com — free)
OPENROUTER_API_KEY  = (from openrouter.ai — free)
HUGGINGFACE_API_KEY = (from huggingface.co — free)
```

## Step 5: Get Free API Keys

### Groq (Fastest — Llama 3.3 70B)
1. Go to [console.groq.com](https://console.groq.com)
2. Sign up free
3. API Keys → Create Key

### NVIDIA NIM (Powerful — Qwen/Kimi)
1. Go to [build.nvidia.com](https://build.nvidia.com)
2. Sign up free (no credit card)
3. Get API key

### OpenRouter (29+ free models)
1. Go to [openrouter.ai](https://openrouter.ai)
2. Sign up free
3. Keys → Create Key

### HuggingFace (Backup)
1. Go to [huggingface.co](https://huggingface.co)
2. Sign up free
3. Settings → Access Tokens → New Token

## Step 6: Deploy

Click **Deploy** — Render will build and deploy automatically.

Your backend URL: `https://vexor-backend-fnow.onrender.com` ✅ **LIVE**

## Step 7: Update CLI Config

Already updated in `vexor/cli/vexor/config.py`:
```python
BACKEND_URL = os.getenv("VEXOR_BACKEND_URL", "https://vexor-backend-fnow.onrender.com")
```

Health check: `https://vexor-backend-fnow.onrender.com/api/v1/health`
