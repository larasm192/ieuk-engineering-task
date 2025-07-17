# 🚦 Traffic Log Analyser – Bot Detection & Traffic Insights

## 📘 Project Overview

This project analyses server log files for a music media startup experiencing periodic downtime due to high traffic. Following the success of their podcast and newsletter, the website began receiving tens of thousands of requests, many suspected to be non-human.

With a small engineering team and limited resources, the goal was to investigate traffic patterns, detect potential bots, and propose mitigation strategies to reduce server strain and improve reliability.

---

## 🎯 Objectives

- Parse and structure raw web server logs
- Identify high-traffic IP addresses and access patterns
- Detect potential bots based on behavior (volume, frequency, repetition)
- Generate a structured dataset for analysis
- Provide actionable recommendations for handling non-human traffic

---

## 🧠 Key Questions Addressed

- Which IPs are generating the most requests?
- Are certain pages being accessed far more than others?
- Are bots or scrapers repeatedly targeting specific endpoints?
- What distinguishes legitimate user traffic from automated activity?

---

## 🛠 Solution Summary

- Built a Python-based log parser using `re` and `pandas`
- Extracted fields such as IP address, country, timestamp, path, HTTP method, status, user-agent, and request duration
- Created utility functions to:
  - Count top IPs, user-agents, and request paths
  - Detect suspicious behavior based on:
    - High request volume
    - Low time intervals between requests
    - Excessive requests to the same path
    - Duplicate or missing user-agent strings
- Exported cleaned data to CSV for further analysis
