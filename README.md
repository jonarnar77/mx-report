# MX-Report

MX-Report is a Python script designed to analyze a domain's email health by inspecting its MX, SPF, DMARC, and DKIM related DNS records. It provides a comprehensive report in text, JSON, or HTML format, helping to identify potential issues with email deliverability and security.

## Features

*   **MX Record Analysis**: Fetches MX records and attempts to identify the email provider (e.g., Google Workspace, Microsoft 365).
*   **SPF Record Validation**:
    *   Retrieves and parses the SPF TXT record.
    *   Breaks down each mechanism and modifier, providing explanations.
    *   Checks for common issues like multiple SPF records or overly permissive `all` mechanisms.
    *   Performs reverse DNS lookups for IP addresses found in `ip4` and `ip6` mechanisms.
*   **DMARC Record Check**:
    *   Retrieves and parses the DMARC record (`_dmarc.<domain>`).
    *   Analyzes the DMARC policy (`p=`), reporting URIs (`rua`, `ruf`), and other tags.
*   **DKIM Record Check**:
    *   Attempts to find DKIM records for commonly used selectors (e.g., `selector1`, `google`).
    *   Allows users to specify custom DKIM selectors for checking.
*   **Comprehensive Health Report**:
    *   Summarizes findings with warnings and recommendations.
    *   Provides an overall health status (GOOD, FAIR, NEEDS ATTENTION).
*   **Multiple Output Formats**: Supports plain text, JSON, and HTML output for easy consumption or integration.

## Prerequisites

*   Python 3.x
*   The `dnspython` library

## Installation

1.  Clone the repository or download the `mx-report.py` script.
2.  Install the required `dnspython` library:
    ```bash
    pip install dnspython
    ```

## Usage

The script is run from the command line, with the domain to analyze as a required argument.

```bash
python mx-report.py <domain> [options]
```

### Arguments

*   `domain`: (Required) The domain name you want to analyze (e.g., `example.com`).

### Options

*   `--dkim-selectors SELECTOR [SELECTOR ...]`: (Optional) A list of specific DKIM selectors to check (e.g., `google selector1 k1`). If not provided, a list of common selectors will be checked.
*   `--format {text,json,html}`: (Optional) The output format for the report. Defaults to `text`.
    *   `text`: Plain text output, suitable for console viewing.
    *   `json`: JSON formatted output, suitable for programmatic use or integration with other tools.
    *   `html`: HTML formatted report, suitable for viewing in a web browser.

## Examples

1.  **Analyze a domain with default text output:**
    ```bash
    python mx-report.py example.com
    ```

2.  **Analyze a domain and specify custom DKIM selectors:**
    ```bash
    python mx-report.py example.com --dkim-selectors s1 s2 mailjet
    ```

3.  **Get the report in JSON format:**
    ```bash
    python mx-report.py example.com --format json
    ```
    To save to a file:
    ```bash
    python mx-report.py example.com --format json > report.json
    ```

4.  **Get the report in HTML format:**
    ```bash
    python mx-report.py example.com --format html
    ```
    To save to a file and open in a browser:
    ```bash
    python mx-report.py example.com --format html > report.html
    # Then open report.html in your web browser
    ```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Created with ❤️ by Jon Arnar Jonsson.