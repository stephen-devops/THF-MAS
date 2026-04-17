# 🐳 Running THF with Docker

This guide will help you run the THF (Threat Hunting Framework) using Docker. No Python installation required!

---

## 📋 Prerequisites

Before you start, make sure you have:

1. **Docker Desktop** installed on your computer
   - Download from: https://www.docker.com/products/docker-desktop
   - Windows users: Make sure WSL 2 is enabled
   - Mac/Linux users: Install Docker Engine or Docker Desktop

2. **Access to your Wazuh environment**
   - OpenSearch host address and credentials
   - Wazuh API host address and credentials

3. **Anthropic API Key**
   - Get one from: https://console.anthropic.com/

---

## 🚀 Quick Start (3 Steps!)

### Step 1: Download the Code

```bash
git clone https://github.com/resilmesh2/THF.git
cd THF
```

### Step 2: Configure Your Environment

1. Copy the example configuration file:
   ```bash
   cp .env.example .env
   ```

2. Open the `.env` file in any text editor and fill in your details:
   ```env
   ANTHROPIC_API_KEY=your-actual-api-key-here
   OPENSEARCH_HOST=your-opensearch-server
   OPENSEARCH_PASSWORD=your-password
   WAZUH_API_HOST=your-wazuh-server
   WAZUH_API_PASSWORD=your-wazuh-password
   ```

   **Important Notes:**
   - If your Wazuh/OpenSearch is running on your **local computer**, use:
     - Windows/Mac: `host.docker.internal`
     - Linux: Your machine's IP address (find it with `hostname -I`)
   - If using remote servers, just enter their IP addresses or hostnames

### Step 3: Start the Application

```bash
docker-compose up
```

That's it! Wait about 1-2 minutes for everything to start up.

---

## 🌐 Accessing the Application

Once the container is running, open your web browser:

- **Main UI**: http://localhost:8501
- **API Documentation**: http://localhost:8030/docs
- **Health Check**: http://localhost:8030/health

**📝 Port Mapping Explained:**
The docker-compose.yml uses port mapping `8030:8000`:
- **8030** = Host port (what you access from your machine)
- **8000** = Container port (where FastAPI runs inside Docker)

This allows the FastAPI backend to run on its default port (8000) inside the container, while being accessible externally on port 8030.

---

## 🎯 Using the Application

1. Go to http://localhost:8501 in your browser
2. Wait for the "API Status: Online" indicator in the sidebar
3. Type your security question in natural language
4. Press Enter and wait for the AI to analyze your Wazuh data

### Example Questions:
- "Show me the top 10 hosts with most alerts this week"
- "Find failed login attempts in the last 24 hours"
- "Which agents are disconnected?"
- "What critical alerts do we have today?"

---

## 🛠️ Common Commands

### Start the application:
```bash
docker-compose up
```

### Start in background (detached mode):
```bash
docker-compose up -d
```

### Stop the application:
```bash
docker-compose down
```

### View logs:
```bash
docker-compose logs -f
```

### Restart the application:
```bash
docker-compose restart
```

### Rebuild after code changes:
```bash
docker-compose up --build
```

---

## ⚠️ Troubleshooting

### Problem: "Cannot connect to OpenSearch"

**Solution:**
- Check your `.env` file has the correct `OPENSEARCH_HOST`
- If Wazuh is on your computer:
  - Windows/Mac: Use `host.docker.internal` instead of `localhost`
  - Linux: Use your machine's IP address (not `localhost`)
- Test connection: `curl -k https://your-opensearch-host:9200`

### Problem: "API Status: Offline" in UI

**Solution:**
- Wait 30-60 seconds - FastAPI takes time to start
- Check logs: `docker-compose logs resilmesh-tap-thf`
- Verify your `ANTHROPIC_API_KEY` is correct in `.env`

### Problem: "Missing required environment variables"

**Solution:**
- Make sure you copied `.env.example` to `.env`
- Open `.env` and fill in all values marked as `REQUIRED`
- Don't leave any required fields as `your-xxx-here`

### Problem: Port already in use

**Solution:**
- Something else is using port 8030 or 8501 on your host machine
- Stop the other application, or change the **host port** in `docker-compose.yml`:
  ```yaml
  ports:
    - "8080:8000"   # Use host port 8080 instead of 8030 (container still uses 8000)
    - "8502:8501"   # Use host port 8502 instead of 8501
  ```

**Note:** Only change the first number (host port). The second number (container port) should remain 8000 for FastAPI and 8501 for Streamlit.

### Problem: Docker build fails

**Solution:**
- Make sure Docker Desktop is running
- Check your internet connection (needed to download packages)
- Try: `docker-compose down` then `docker-compose up --build`

---

## 🔧 Advanced Configuration

### Enable Redis Caching (Optional)

1. Edit `docker-compose.yml`
2. Uncomment the Redis section (remove the `#` symbols)
3. Update `.env`:
   ```env
   REDIS_HOST=resilmesh-redis
   ENABLE_CACHING=true
   ```
4. Restart: `docker-compose up`

### Change Resource Limits

Edit `docker-compose.yml` to adjust CPU and memory:

```yaml
deploy:
  resources:
    limits:
      cpus: '4'      # Use 4 CPU cores
      memory: 8G     # Use 8GB RAM
```

### Persist Logs

Logs are automatically saved to `./logs` directory on your host machine.

---

## 🔒 Security Best Practices

1. **Never commit your `.env` file** - It contains secrets!
2. **Use strong passwords** for OpenSearch and Wazuh
3. **Keep your Anthropic API key private**
4. **Use HTTPS** when connecting to OpenSearch/Wazuh
5. **Run on private networks** - Don't expose to the internet without authentication

---

## 📊 Monitoring

### Check if services are healthy:
```bash
docker-compose ps
```

All services should show `healthy` status.

### View real-time logs:
```bash
# All services
docker-compose logs -f

# Just the main app
docker-compose logs -f resilmesh-tap-thf
```

### Check resource usage:
```bash
docker stats
```

---

## 🧹 Cleanup

### Remove containers and keep data:
```bash
docker-compose down
```

### Remove everything (including volumes):
```bash
docker-compose down -v
```

### Remove Docker images:
```bash
docker rmi thf:latest
```

---

## 🆘 Getting Help

If you're stuck:

1. **Check the logs**: `docker-compose logs -f resilmesh-tap-thf`
2. **Verify your `.env` file** has all required values
3. **Test connectivity** to your Wazuh/OpenSearch servers
4. **Open an issue** on GitHub with:
   - Your Docker version: `docker --version`
   - Error messages from logs
   - Your operating system

---

## 📚 Additional Resources

- **Main Documentation**: See `README.md` for detailed feature information
- **API Documentation**: http://localhost:8030/docs (when running)
- **Docker Documentation**: https://docs.docker.com/
- **Wazuh Documentation**: https://documentation.wazuh.com/

---

## 🎉 You're All Set!

Your THF instance should now be running. Go to http://localhost:8501 and start hunting threats!

**Pro Tip**: Use the example queries in the sidebar to get started quickly.
