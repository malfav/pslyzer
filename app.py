from flask import Flask, request, render_template_string
import base64
import re
import requests

app = Flask(__name__)

# Define the dark military-themed template with added sections
TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Analysis Lab</title>
    <style>
        body { background-color: #0b0b0b; color: #dcdcdc; font-family: 'Courier New', Courier, monospace; }
        .container { width: 85%; margin: auto; padding: 20px; background-color: #1a1a1a; border-radius: 8px; }
        h1, h2 { color: #00ff00; text-shadow: 1px 1px 2px #000; }
        form { margin-bottom: 20px; }
        textarea, button { padding: 12px; margin: 10px 0; border: 1px solid #333; border-radius: 5px; background-color: #2b2b2b; color: #dcdcdc; }
        textarea { width: 100%; height: 200px; resize: vertical; }
        button { cursor: pointer; background-color: #007700; }
        button:hover { background-color: #005500; }
        .output { background-color: #2b2b2b; padding: 15px; border-radius: 5px; border: 1px solid #333; }
        .url-table, .command-table, .ip-table, .file-table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        .url-table th, .command-table th, .ip-table th, .file-table th, .url-table td, .command-table td, .ip-table td, .file-table td { padding: 12px; border: 1px solid #444; }
        .url-table th, .command-table th, .ip-table th, .file-table th { background-color: #333; color: #00ff00; }
        .url-table tr:nth-child(even), .command-table tr:nth-child(even), .ip-table tr:nth-child(even), .file-table tr:nth-child(even) { background-color: #1e1e1e; }
        pre { background-color: #2b2b2b; padding: 10px; border: 1px solid #333; border-radius: 5px; white-space: pre-wrap; }
        .map { width: 100%; height: 400px; border: 1px solid #333; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Threat Analysis Lab</h1>
        <form method="post" action="/analyze">
            <textarea name="script" placeholder="Paste your PowerShell script here..."></textarea><br>
            <button type="submit">Analyze Script</button>
        </form>

        {% if analysis_result %}
            <h2>Analysis Result</h2>
            <div class="output">
                <h3>Embedded URLs</h3>
                <table class="url-table">
                    <tr><th>URL</th></tr>
                    {% for url in analysis_result['urls'] %}
                        <tr><td>{{ url }}</td></tr>
                    {% endfor %}
                </table>

                {% if analysis_result['decoded_content'] %}
                    <h3>Decoded Content</h3>
                    <pre>{{ analysis_result['decoded_content'] }}</pre>
                {% endif %}

                <h3>File Download Details</h3>
                <table class="file-table">
                    <tr><th>File Name</th><th>Download Path</th><th>Description</th></tr>
                    {% for file_name, path, description in analysis_result['file_downloads'] %}
                        <tr>
                            <td>{{ file_name }}</td>
                            <td>{{ path }}</td>
                            <td>{{ description }}</td>
                        </tr>
                    {% endfor %}
                </table>

                <h3>PowerShell Commands Used</h3>
                <table class="command-table">
                    <tr><th>Command</th><th>Count</th></tr>
                    {% for command, count in analysis_result['commands'].items() %}
                        <tr><td>{{ command }}</td><td>{{ count }}</td></tr>
                    {% endfor %}
                </table>

                <h3>IP Information</h3>
                <table class="ip-table">
                    <tr><th>Domain</th><th>IP</th><th>City</th><th>Region</th><th>Country</th><th>ISP</th></tr>
                    {% for domain, info in analysis_result['ip_info'].items() %}
                        <tr>
                            <td>{{ domain }}</td>
                            <td>{{ info['query'] if 'query' in info else 'N/A' }}</td>
                            <td>{{ info['city'] if 'city' in info else 'N/A' }}</td>
                            <td>{{ info['regionName'] if 'regionName' in info else 'N/A' }}</td>
                            <td>{{ info['country'] if 'country' in info else 'N/A' }}</td>
                            <td>{{ info['isp'] if 'isp' in info else 'N/A' }}</td>
                        </tr>
                    {% endfor %}
                </table>

                {% if analysis_result['ip_map'] %}
                    <h3>IP Location Map</h3>
                    <iframe class="map" src="{{ analysis_result['ip_map'] }}" frameborder="0"></iframe>
                {% endif %}
            </div>
        {% endif %}
    </div>
</body>
</html>
'''

def extract_urls(script):
    url_pattern = re.compile(r'(https?://[^\s]+)')
    return url_pattern.findall(script)

def decode_script(script):
    decoded_content = ""

    try:
        decoded_base64 = base64.b64decode(script).decode('utf-8', 'ignore')
        if re.search(r'[^\x00-\x7F]', decoded_base64):
            decoded_content += f"Base64 decode: {decoded_base64}\n"
    except Exception:
        pass

    xor_decoded = ""
    for i in range(1, 256):
        decoded = ''.join(chr(ord(c) ^ i) for c in script)
        if all(32 <= ord(c) <= 126 or c in "\n\r\t" for c in decoded):
            xor_decoded += f"XOR decode with key {i}: {decoded}\n"
    
    if xor_decoded:
        decoded_content += xor_decoded

    try:
        rot13_table = str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm")
        decoded_rot13 = script.translate(rot13_table)
        if re.search(r'[^\x00-\x7F]', decoded_rot13):
            decoded_content += f"ROT13 decode: {decoded_rot13}\n"
    except Exception:
        pass

    return decoded_content.strip() if decoded_content.strip() else None

def get_ip_info(url):
    try:
        domain = re.sub(r'https?://', '', url).split('/')[0]
        response = requests.get(f"http://ip-api.com/json/{domain}")
        if response.status_code == 200:
            return response.json()
        return {"error": "Unable to get IP information"}
    except Exception as e:
        return {"error": str(e)}

def get_ip_map(ip_info):
    if 'query' in ip_info:
        ip = ip_info['query']
        return f"https://www.bing.com/maps/embed?h=400&w=800&cp={ip}&lvl=15&sty=r&shd=1"
    return None

def extract_file_downloads(script):
    file_downloads = []
    download_pattern = re.compile(r'(?:Start-Process\s*\(\s*"\$env:[^"]*\\([^\\"]+)"\s*\))', re.IGNORECASE)
    path_pattern = re.compile(r'Start-Process\s*\(\s*"\$env:[^"]*(\\[^"]+)"\s*\)', re.IGNORECASE)

    for match in download_pattern.finditer(script):
        file_name = match.group(1)
        path_match = path_pattern.search(script)
        path = path_match.group(1) if path_match else "Unknown"
        description = "Common path used to avoid detection or for persistence." if path != "Unknown" else "Unknown path"
        file_downloads.append((file_name, path, description))
    
    return file_downloads

@app.route('/', methods=['GET'])
def index():
    return render_template_string(TEMPLATE)

@app.route('/analyze', methods=['POST'])
def analyze():
    script = request.form['script']
    
    urls = extract_urls(script)
    decoded_content = decode_script(script)
    file_downloads = extract_file_downloads(script)
    
    ip_info = {}
    ip_map = None
    for url in urls:
        domain = re.sub(r'https?://', '', url).split('/')[0]
        info = get_ip_info(url)
        ip_info[domain] = info
        if not ip_map:
            ip_map = get_ip_map(info)
    
    analysis_result = {
        'urls': urls,
        'decoded_content': decoded_content,
        'commands': {cmd: script.count(cmd) for cmd in ['Invoke-WebRequest', 'Invoke-Expression', 'Start-Process', 'New-Object', 'DownloadFile']},
        'file_downloads': file_downloads,
        'ip_info': ip_info,
        'ip_map': ip_map
    }
    
    return render_template_string(TEMPLATE, analysis_result=analysis_result)

if __name__ == '__main__':
    app.run(debug=True)
