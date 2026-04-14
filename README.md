# Edge-Based Secure QR Sandbox 🛡️

**Author:** Mateusz Glebocki  
**Institution:** Liverpool Hope University  
**Degree:** Computer Science  

[![Python 3.12.1](https://img.shields.io/badge/python-3.12.1-blue.svg)](https://www.python.org/downloads/)
[![Architecture: MVC](https://img.shields.io/badge/Architecture-MVC-brightgreen.svg)]()

A highly optimized, multithreaded Python application designed to detect physical Quishing (QR Phishing) attacks in real-time. Built on a strict **Model-View-Controller (MVC)** architecture, this edge-based sandbox utilizes deterministic mathematical heuristics and OS-level thread concurrency to assess threat vectors offline, preventing zero-day attacks without degrading the user experience.

This directory contains the complete source code, heuristic engines, and empirical evaluation scripts discussed in the dissertation.

---

## 📂 Project Structure

* `app.py`: The main Orchestration (Controller) and Dashboard (View) layer. Run this to start the application.
* `scanner.py`: The OpenCV hardware interface and PyZbar optical matrix decoder.
* `analyzer.py`: The multithreaded Security Engine (Model) containing all heuristic strategies.
* `benchmark.py`: Automated performance profiling script utilizing `time.perf_counter()`.
* `confusion_matrix_evaluation.py`: Security efficacy script to test the 40-URL synthetic dataset.
* `tests.py`: Automated unit tests utilizing `unittest.mock` for isolated environment verification.
* `config.json`: Configuration file containing targeted brands for the Levenshtein distance algorithm.

---

## 🛠️ Installation & Setup

**1. Extract the Files:**
Extract this `.zip` folder to a designated location on your local machine.

**2. Open in PyCharm (Recommended):**
It is highly recommended to open this extracted folder directly as a project in **JetBrains PyCharm** to ensure pathing and virtual environments resolve correctly.

**3. Configure the Environment:**
Ensure your IDE interpreter is set to use **Python 3.12.1**. Open the integrated terminal within PyCharm and install the required dependencies:
```bash
pip install -r requirements.txt
(Core dependencies include: opencv-python, pyzbar, requests, numpy)

4. API Key Configuration (Optional but Recommended):
To enable the reactive Google Safe Browsing API integration, create a file named .env in the root directory of this folder and add your API key:
GOOGLE_SAFE_BROWSING_KEY=your_api_key_here
(Note: If no key is provided, the system will gracefully bypass this specific check and rely purely on the local mathematical heuristics).

📋 Standard Operating Procedure (How to Grade/Run)
This system is divided into the core end-user application and a suite of diagnostic profiling tools used for the Chapter 4 Evaluation.

1. Launching the Sandbox (End-User Mode)
To start the live OpenCV webcam feed and the Tkinter dashboard:

Bash
python app.py
Usage: Hold a physical QR code (from a phone or printed paper) up to the webcam. Press q to acquire an optical lock. The system will instantly decode it, dispatch the background threads, and update the dashboard with a SAFE, WARNING, or MALICIOUS state.

2. Running the Performance Benchmark
To test the CPU latency and multithreaded execution speed across 30 iterations of Best-Case, Mid-Case, and Worst-Case payloads:

Bash
python benchmark.py
Expected Output: A formatted CLI table displaying Min, Max, and Mean execution times (proving the sub-3ms latency).

3. Evaluating Security Efficacy
To test the mathematical bounds of the heuristic engine against the synthetic 40-URL dataset (including Zero-Day Phishing, Combosquatting, and Homograph attacks):

Bash
python confusion_matrix_evaluation.py
Expected Output: The resulting True Positives, True Negatives, False Positives, False Negatives, and overall Accuracy/Recall metrics discussed in the dissertation.

4. Running the Isolated Unit Tests
To verify the structural integrity of the Object-Oriented heuristics and mock external API dependencies:

Bash
python -m unittest tests.py -v
Disclaimer: Developed explicitly for Academic Evaluation. Do not deploy as a standalone corporate firewall without further cross-platform kernel profiling.