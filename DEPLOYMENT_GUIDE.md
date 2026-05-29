# Deployment Guide: Next-Gen IDS/IPS System

This guide covers the installation and configuration of the advanced AI-Powered IDS/IPS with TLS decryption and LLM integration.

## 1. Prerequisites

- **Python 3.8+**
- **Root/Admin Privileges** (required for packet capture and iptables)
- **OpenAI API Key** (for intelligent detection and agency verification)
- **mitmproxy** installed (`pip install mitmproxy`)

## 2. Setting Up TLS Decryption

To decrypt HTTPS traffic, follow these steps:

1.  **Start the Sniffer**: Run `python secure_sniffer.py`. This starts a proxy on port `8080`.
2.  **Configure Proxy**: Set your device or browser's HTTP proxy to `127.0.0.1:8080`.
3.  **Install CA Certificate**:
    - Visit [mitm.it](http://mitm.it) while the sniffer is running.
    - Download and install the certificate for your OS.
    - **Important**: On Windows/macOS, ensure the certificate is moved to the "Trusted Root Certification Authorities" store.

## 3. Configuring Generative AI (GPT)

The system uses GPT-4 to analyze novel threats and identify Trusted Agencies.

1.  **Environment Variable**: Set your API key in your shell:
    ```powershell
    $env:OPENAI_API_KEY = "your-key-here"
    ```
2.  **Manual Config**: Alternatively, edit `realtime_ids.py` and update the `CONFIG` section:
    ```python
    "openai_api_key": "your-key-here"
    ```

## 4. Running the System

### Phase 1: Training (Unsupervised/Supervised)
If you have your own dataset (CSV), run:
```bash
python ids_ips_trainer.py
```
This will generate the model artifacts in the `ids_output` folder.

### Phase 2: Real-Time Monitoring
Start the real-time engine (requires sudo/root):
```bash
sudo python realtime_ids.py
```

### Phase 3: Visibility & Reporting
- **Live Dashboard**:
  ```bash
  streamlit run dashboard.py
  ```
- **Excel Audit Report**:
  ```bash
  python report_generator.py
  ```

## 5. Trusted Agency Feature
The system automatically identifies traffic from agencies like Google, Microsoft, and Cloudflare. 
- To add a custom agency, update the prompt logic in `llm_analyzer.py` or add their IP ranges to the whitelist in `realtime_ids.py`.

## 6. Email Notifications
To enable email alerts, update the `CONFIG` in `realtime_ids.py`:
- `email_enabled`: `True`
- `smtp_user`: Your email address
- `smtp_password`: Your App Password (for Gmail, use App Passwords, not your main password)
- `alert_recipient`: Admin email address

---
**Security Note**: This tool is for educational and authorized defensive purposes only. Decrypting traffic on networks you do not own or have permission for is illegal and unethical.
