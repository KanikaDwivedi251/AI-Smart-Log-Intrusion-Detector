# AI Smart Intrusion and Anomaly Detector

Build a single-page, state-of-the-art cybersecurity monitoring dashboard interface named "AI-Powered Smart Log Intrusion & Anomaly Detector". The dashboard should have a sleek, sophisticated "dark-mode" theme, utilizing deep blacks, charcoals, electric blues, and warning reds for accents, resembling an enterprise Security Operations Center (SOC).

The layout must include the following distinct modules arranged clearly:

1. **PROJECT HEADER & NAVIGATION:** A top bar with the main title: "AI-Powered Smart Log Intrusion & Anomaly Detector with Active Threat Response and Generative Insights". It should also have a dynamic "System Status: Monitoring" indicator and a settings icon.

2. **LOG INGESTION CONTROL PANEL:** A prominent card/section allowing the user to either:
   - "Upload Log File" (Button with file input icon)
   - "Start Simulated Live-Stream Mode" (Toggle switch).

3. **REAL-TIME THREAT METRICS (KPIs):** Four numeric data cards displaying key statistics with slight glow effects:
   - "Total Logs Scanned"
   - "Anomalies Detected"
   - "Auto-Blocked IPs"
   - "Current Threat Score (%)"

4. **INTERACTIVE LIVE THREAT MAP:** A large central card featuring a simplified world map visualization (simulating Leaflet.js). This map should display dynamic, pulsating red "attack source" points connected by lines to a single "target server" icon. The countries should be geo-located from attacker IPs.

5. **AI DETECTED ANOMALIES TABLE:** A detailed tabular view showing recent detected threats with the following columns:
   - Timestamp
   - Attacker IP (with country flag icon)
   - Severity (Low, Medium, High)
   - Attack Type (e.g., Brute Force, SQLi)
   - Proposed Action

6. **GENERATIVE AI THREAT INSIGHTS & REMEDIATION PANEL:** Two adjacent cards:
   - **Card A (Generative AI Summary):** "AI Incident Report" box with AI icon, showing generated plain-English text explaining the current major attack.
   - **Card B (Active Response):** "Recommended Active Response" box showing a pre-generated terminal command (e.g., "ufw deny from 185.10.10.1") and a large, red "Execute One-Click Firewall Block" button.

7. **REAL-TIME ALERTS & LOG STREAM:** A smaller side-panel displaying a scrolling feed of the raw log lines as they are ingested, with critical anomaly lines highlighted in bright red.

The overall design should feel professional, cutting-edge, data-heavy, but incredibly clean and intuitive. Include tooltips on complex metrics.

This project was built with [Lovable](https://lovable.dev).

**Live app**: https://watchtower-ai-digest.lovable.app

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/5978dbdb-2751-4c03-ad95-6ec80e749331).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
