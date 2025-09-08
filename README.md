# Web Vulnerability Scanner 🕸️

This is a Python-based web application vulnerability scanner designed to detect common vulnerabilities such as **Cross-Site Scripting (XSS)** and **SQL Injection**. It features a user-friendly Flask web interface for easy scanning and viewing results, and it generates detailed scan reports in JSON, HTML, and PDF formats.

-----

## Prerequisites

  * **Python 3.x** installed on your system.
  * **Git** (optional, but recommended for cloning the repository).
  * **Python virtual environment (venv)** is highly recommended to manage project dependencies.

-----

## Setup and Installation

Follow these steps to get the scanner up and running on your local machine.

### 1\. Clone the Repository

Clone the project from its GitHub repository (or download the ZIP file and extract it).

```bash
git clone https://github.com/Poojyesh1/Project.git
cd web-vulnerability-scanner
```

### 2\. Create and Activate a Virtual Environment

It's a best practice to use a virtual environment to avoid conflicts with your system's Python packages.

**Windows:**

```bash
python -m venv venv
venv\Scripts\activate
```

**Linux/macOS:**

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3\. Install Dependencies

Once your virtual environment is active, install the required libraries using `pip`.

```bash
pip install -r requirements.txt
```

-----

## Running the Scanner

You can run the scanner using either the web interface or directly from the command line.

### Web Interface 🌐

1.  **Start the Flask web server:**

    ```bash
    python app.py
    ```

2.  **Open your web browser** and navigate to:

    `http://127.0.0.1:5000`

3.  **Enter the target URL** you want to scan (make sure to include `http://` or `https://`) and click **"Scan"**.

4.  **View the results** directly on the web page. Any vulnerabilities found will be listed with details.

### Command Line Interface (CLI) 💻

If you prefer to run a scan without the web UI, you can use the command line.

```bash
python scanner.py http://example.com
```

Replace `http://example.com` with your target URL. The scan results will be printed to the console, and detailed reports will be saved in the `reports/` folder.

-----

## Scan Reports 📄

After a scan is complete, detailed reports are saved in the `reports/` directory with a timestamp for easy identification.

  * **JSON report:** `scan_report_<timestamp>.json`
  * **HTML report:** `scan_report_<timestamp>.html`
  * **PDF report:** `scan_report_<timestamp>.pdf`

You can open the HTML and PDF files with your web browser and a PDF viewer, respectively.

-----

## Notes and Ethical Usage ⚠️

  * Always ensure the **target URL is accessible** and includes the correct scheme (`http://` or `https://`).
  * The tool currently focuses on **XSS and SQL Injection vulnerabilities**.
  * This tool is **easily extendable** to include more vulnerability modules in the future.
  * **Use this tool ethically.** Only scan websites that you own or for which you have explicit authorization. Unauthorized scanning is illegal and unethical.
