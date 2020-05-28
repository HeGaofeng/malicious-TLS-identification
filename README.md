# Introduction

Identify malicious TLS flows by VirusTotal.
This tool can be used with [maliciousTrafficDownload]([https://github.com/HeGaofeng/maliciousTrafficDownload](https://github.com/HeGaofeng/maliciousTrafficDownload)) and [TLS-Information-Extraction]([https://github.com/HeGaofeng/TLS-Information-Extraction](https://github.com/HeGaofeng/TLS-Information-Extraction)) to construct malicious TLS traffic dataset.

# How to use

1. Use  [TLS-Information-Extraction]([https://github.com/HeGaofeng/TLS-Information-Extraction](https://github.com/HeGaofeng/TLS-Information-Extraction))  to extract all metainformation for TLS flows.
2. Add your VirusTotal API key in the code: 'x-apikey: your-key'
3. In Linux shell, run ./malicious-TLS-identification.sh path-of-ssl_log-files

# Principles
The code search the domain name or IP address in VirusTotal. If more than three engines judge that the name or IP address is malicious, the corresponding flow is identified as malicious.

Blacklists and whitelists are also used to reduce the searching.

# Note
One can request an acadamic API key from VirusTotal, which support 20,000 accessing every day. It is free for six month.
