# NoN0is3 – Silent Recon

NoN0is3 is a passive-first reconnaissance tool focused on collecting high-value attack surface with minimal noise.  
It is designed for security researchers, bug bounty hunters, and penetration testers who want structured, filtered recon output instead of large volumes of irrelevant data.

Created by **ShAd0W-byte**

---

## What NoN0is3 Does

- Passive subdomain discovery (API-based + public sources)
    
- Multi-source historical URL collection
    
- Intelligent filtering to remove low-value noise
    
- Concurrent URL validation
    
- Optional WordPress enumeration
    
- Cross-platform support (Linux, Windows)
    

---

# Installation

## Linux (Kali, Ubuntu, Debian, etc.)

### Step 1 — Clone the Repository

```
git clone https://github.com/ShAd0W-byte/nonoise.git
cd nonoise
```

### Step 2 — Create a Python Virtual Environment (Required on Kali)

Kali Linux and similar systems restrict global pip installations.  
You must use a virtual environment.

```
python3 -m venv venv
source venv/bin/activate
```

Your terminal should now display `(venv)`.

### Step 3 — Install Dependencies

```
pip install -r requirements.txt
pip install -e .
```

Test installation:

```
nonoise -h
```

---

## Windows Installation

### Step 1 — Clone Repository

```
git clone https://github.com/ShAd0W-byte/nonoise.git
cd nonoise
```

### Step 2 — Create Virtual Environment

```
python -m venv venv
venv\Scripts\activate
```

### Step 3 — Install

```
pip install -r requirements.txt
pip install -e .
```

Test:

```
nonoise -h
```

---

# First-Time Usage (Recommended)

If this is your first time using NoN0is3, use interactive mode:

```
nonoise --interactive
```

Interactive mode guides you step-by-step and reduces input mistakes.

---

# Command Line Usage

```
nonoise [options]
```

---

## Options Explained

### -d, --domain

Specifies the target domain.

Example:

```
nonoise -d example.com
```

Required unless using interactive mode.

---

### -t, --threads

Sets the number of concurrent workers used for URL validation.

Default: 70

Higher value increases speed but may cause:

- Rate limits
    
- Timeouts
    
- Connection errors
    

Example:

```
nonoise -d example.com -t 100
```

---

### -w, --wordpress

Enables WordPress-specific enumeration.

Scans common WordPress paths and assets.

Example:

```
nonoise -d example.com -w
```

---

### -sd, --skip-subdomains

Skips passive subdomain discovery.

Useful if:

- You already have subdomains
    
- You want faster execution
    
- You do not want to use API-based discovery
    

Example:

```
nonoise -d example.com -sd
```

---

### -vapi, --virustotal-api

Sets or updates your VirusTotal API key.

VirusTotal is used for passive subdomain discovery.

Get your API key here:  
[https://www.virustotal.com/](https://www.virustotal.com/)

Example:

```
nonoise -vapi YOUR_API_KEY
```

Important:

- You only need to set this once.
    
- The key is stored locally.
    
- You do NOT need to re-enter it every time you run the tool.
    
- Running the command again will overwrite the existing key.
    

---

### -sapi, --securitytrails-api

Sets or updates your SecurityTrails API key.

SecurityTrails is used for additional passive subdomain discovery.

Get your API key here:  
[https://securitytrails.com/](https://securitytrails.com/)

Example:

```
nonoise -sapi YOUR_API_KEY
```

Important:

- You only need to set this once.
    
- The key is stored locally.
    
- Running the command again will replace the stored key.
    

---

## API Key Storage

API keys are stored locally in:

Linux:

```
~/.config/nonoise/config.json
```

Windows:

```
%APPDATA%/nonoise/config.json
```

You can manually delete this file if you want to reset all stored keys.

If API keys are not configured:

- Subdomain discovery will be limited
    
- Some passive sources will not be used
    

---

### -i, --interactive

Launches guided interactive mode.

Recommended for beginners and first-time users.

Example:

```
nonoise --interactive
```

---

### -h, --help

Displays help menu.

---

### -v, --version

Displays tool version.

---

# Domain Format Warning

Enter the exact domain format you want to scan.

If the target uses:

```
www.example.com
```

Enter:

```
www.example.com
```

If it uses:

```
example.com
```

Enter:

```
example.com
```

Incorrect format may affect subdomain discovery and URL validation.

---

# Output

NoN0is3 generates:

- `nonoise_output/`
    
    - `{domain}_visited.txt` (validated URLs with status codes)
        
- `subdomains_discovered.txt` (if enabled)
    
- `wordpress_results.txt` (if WordPress mode enabled)
    

---

# Troubleshooting

## Module Not Found

Ensure:

- Virtual environment is activated
    
- Installation completed successfully
    
- You are running inside the project directory (if using editable mode)
    

Activate again if needed:

Linux:

```
source venv/bin/activate
```

Windows:

```
venv\Scripts\activate
```

---

## Permission Denied (Kali)

Do not install globally.

Always use a virtual environment.

---

## API Keys Not Working

Check:

1. Did you set the key using:
    
    ```
    nonoise -vapi YOUR_KEY
    ```
    
    or
    
    ```
    nonoise -sapi YOUR_KEY
    ```
    
2. Verify the config file exists:
    
    ```
    ~/.config/nonoise/config.json
    ```
    
3. If needed, reset keys:
    
    - Delete the config.json file
        
    - Re-enter API keys
        

---

## API Rate Limits

If you see API-related errors:

- Reduce thread count
    
- Wait before re-running
    
- Check your API dashboard for quota limits
    

---

## Timeouts or Connection Errors

Possible causes:

- Thread count too high
    
- Network instability
    
- Target rate limiting
    
- WAF blocking automated requests
    

Solution:

Lower thread count:

```
nonoise -d example.com -t 40
```

---

## Command Not Found

If `nonoise` command does not work:

Run directly using:

```
python -m nonoise -d example.com
```

If this works, your PATH may not include the virtual environment's scripts directory.

---

# Disclaimer

This tool is intended for authorized security testing and educational purposes only.  
Always obtain proper authorization before scanning any domain.

The author, ShAd0W-byte, is not responsible for misuse.

---

# License

This project is licensed under the MIT License.

---

# Version

v0.1.0 — Initial Release

---