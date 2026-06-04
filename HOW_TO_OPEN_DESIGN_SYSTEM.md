# How to Open and Use the SudoSOC Design System & Console

Modern web browsers restrict loading separate JavaScript/JSX files locally (`file://` protocol) due to **CORS (Cross-Origin Resource Sharing)** security policies. This is why double-clicking the original `index.html` in the subfolder can result in a blank black screen. 

To give you the smoothest, most premium experience, we have provided **two ways** to launch and explore your new Security Operations Console design.

---

## Method 1: The Zero-Configuration Standalone Version (Recommended ⚡)

We have compiled the entire console (all React JSX components, the twinkling background canvas, styling tokens, and telemetry charts) into a single, fully-contained HTML file in the root of your workspace:

📂 **File Name:** `SudoSOC_Console_Standalone.html`  
🔗 **Path:** [SudoSOC_Console_Standalone.html](file:///c:/Users/hp/Downloads/sudosoc_2026/IDS_IPS_TRAINER/SudoSOC_Console_Standalone.html)

### How to open it:
1. Simply **double-click** the `SudoSOC_Console_Standalone.html` file in your Windows File Explorer.
2. It will open instantly in any web browser (Chrome, Edge, Firefox, Brave, etc.) directly from your hard drive.
3. **Zero server setup, zero terminal commands, and absolutely no CORS errors!**

---

## Method 2: The Local Web Server Version (Full Developer Experience 🛠️)

If you want to view the fully-modular version consisting of separate React JSX files (`ui.jsx`, `Chrome.jsx`, `Overview.jsx`, `Analytics.jsx`, etc.), you can run a lightweight, local web server using Python (which is already configured on your system).

We have provided a automated quick-start script in your workspace:

📂 **Server Script:** `start_console.py`  
📂 **PowerShell Executable:** `start_console.ps1`

### How to run it:
* **Option A (One-click):** Right-click [start_console.ps1](file:///c:/Users/hp/Downloads/sudosoc_2026/IDS_IPS_TRAINER/start_console.ps1) and choose **"Run with PowerShell"**.
* **Option B (Terminal):** Open your PowerShell / Command Prompt inside the workspace directory and execute:
  ```bash
  python start_console.py
  ```

### What this does:
1. It starts a lightweight, silent TCP server on **`http://localhost:8080`**.
2. It **automatically opens your web browser** directly to the live dashboard page.
3. Because the files are served over a local network connection, your browser will load all separate components with **zero CORS restrictions**.
4. To stop the server, simply switch back to the terminal window and press **`Ctrl + C`**.

---

## 🖥️ Interactive Features to Explore in the Console
Once you open the dashboard, try interacting with these premium features:
* **Twinkling Telemetry Background:** Notice the ambient, live telemetry grid behind the interface with red and white cells dynamically fading in, bright glowing red dots pulsing, and a slow diagonal sweep effect. The chrome headers use frosted glass backdrop-blur, showing the background cleanly.
* **Responsive Multi-View Navigation:** Click on the left navigation rail (**Overview**, **Flow Analytics**, **Predict**, **Intelligence**) to seamlessly switch pages. The active state indicator updates automatically.
* **Real-time Alert Stream:** On the **Overview** page, watch threat alerts slide in live from the top. Use the **LIVE** toggle button in the top bar to pause or resume the stream.
* **LLM Slide-in Drawer:** Click on any alert row in the live feed. A dedicated details drawer will slide in from the right, mapping the threat to its exact **MITRE ATT&CK** technique and streaming an live-typed analysis report using simulated Qwen/Llama intelligence.
* **Automated Action Alerts:** Inside the detail drawer, click **"Block IP"** or **"Isolate"** to trigger automated IPS rule updates. A tactical confirmation toast notifications will animate at the bottom.
* **Interactive ML Predict Verdicts:** Go to the **Predict** view. Adjust the **Payload entropy** input value (e.g., above 7.5) or destination ports (e.g., 4444) and click **"Predict verdict"**. The custom stack engine will immediately run a mock prediction, flashing the result panel (Green for benign, Red for hostile) and displaying a smooth animation of confidence scores and class probabilities.
* **Intelligence Internals:** Navigate to the **Intelligence** view to inspect Online Learning drift metrics, interactive MITRE ATT&CK technique bars, live-generated Sigma and Suricata rules, and non-decrypted encrypted TLS traffic telemetry.
