package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Estrutura para enviar ao Elasticsearch
type WebEnum struct {
	Timestamp                  time.Time `json:"@timestamp"`
	ServerAddress              string    `json:"server.address"`
	ServerDomain               string    `json:"server.domain"`
	ServerIP                   string    `json:"server.ip"`
	ServerPort                 int64     `json:"server.port"`
	NetworkProtocol            string    `json:"network.protocol"`
	URLPath                    string    `json:"url.path"`
	HTTPResponseStatusCode     int64     `json:"http.response.status_code"`
	URLOriginal                string    `json:"url.original"`
	URLFull                    string    `json:"url.full"`
	VulnerabilityScannerVendor string    `json:"vulnerability.scanner.vendor"`
}

// Variáveis globais
var (
	target        string
	url2          string
	subdomain     string
	ip            string
	headers       map[string]string
	elasticURL    string
	authUser      string
	authPassword  string
	scanner       string
	x             string
	containerName string
	saida         string
	result        []string
	hora          string
)

func init() {
	// Verifica se os argumentos necessários foram fornecidos
	if len(os.Args) < 5 {
		fmt.Println("Uso: programa <target> <url2> <subdomain> <ip>")
		os.Exit(1)
	}

	// Recebe os argumentos da linha de comando
	target = os.Args[1]
	url2 = os.Args[2]
	subdomain = os.Args[3]
	ip = os.Args[4]

	// Define as variáveis necessárias
	elasticURL = fmt.Sprintf("https://localhost:9200/%s-webenum/_doc?refresh", target)
	authUser = "admin"
	authPassword = "StrongAdmin123!"
	scanner = "wayback"
	hora = time.Now().Format(time.RFC3339)

	// Gera um UUID e extrai a primeira parte
	xUUID := uuid.New().String()
	x = strings.Split(xUUID, "-")[0]

	// Monta o nome do contêiner e o nome do arquivo de saída
	containerName = fmt.Sprintf("%s-%s-wayback", target, x)
	saida = fmt.Sprintf("wayback-%s.xml", x)

	// Define os headers
	headers = map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}
}

func executa() {
	// Build the command arguments
	args := []string{
		"run",
		"--rm",
		"--name",
		containerName,
		"kali-recon",
		"waybackurls",
		url2,
	}

	// For debugging
	fmt.Println("Comando sendo executado:")
	fmt.Println("docker", strings.Join(args, " "))

	// Execute the command
	cmd := exec.Command("docker", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Erro ao executar o comando: %v\n", err)
		fmt.Printf("Saída do comando:\n%s\n", string(output))
		result = []string{}
		return
	}

	// Divide a saída em linhas
	result = strings.Split(strings.TrimSpace(string(output)), "\n")
}

func parse() {
	executa()
	if len(result) == 0 {
		fmt.Println("Nenhum resultado obtido do waybackurls.")
		return
	}

	for _, sistema := range result {
		if sistema != "" && sistema != "\n" {
			dicWeb := make(map[string]string)
			dicWeb["network.protocol"] = strings.Split(sistema, ":")[0]

			var serverPort string
			parts := strings.Split(sistema, ":")
			if len(parts) > 2 {
				// Tenta obter a porta
				portAndPath := parts[2]
				port := strings.Split(portAndPath, "/")[0]
				serverPort = port
			} else {
				if dicWeb["network.protocol"] == "http" {
					serverPort = "80"
				} else {
					serverPort = "443"
				}
			}
			dicWeb["server.port"] = serverPort

			pathParts := strings.Split(sistema, "/")
			if len(pathParts) == 3 {
				dicWeb["url.path"] = "/"
				dicWeb["url.original"] = sistema
			} else {
				dicWeb["url.path"] = "/" + strings.Join(pathParts[3:], "/")
				dicWeb["url.original"] = dicWeb["network.protocol"] + "://" + pathParts[2]
			}

			// Constrói a estrutura WebEnum
			data := WebEnum{
				Timestamp:                  time.Now(),
				ServerAddress:              subdomain,
				ServerDomain:               subdomain,
				ServerIP:                   ip,
				ServerPort:                 parseInt64(serverPort),
				NetworkProtocol:            dicWeb["network.protocol"],
				URLPath:                    dicWeb["url.path"],
				HTTPResponseStatusCode:     200,
				URLOriginal:                dicWeb["url.original"],
				URLFull:                    dicWeb["url.original"] + dicWeb["url.path"],
				VulnerabilityScannerVendor: scanner,
			}

			// Envia os dados para o Elasticsearch
			sendToElastic(data)
		}
	}
}

func parseInt64(s string) int64 {
	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return i
}

func sendToElastic(data WebEnum) {
	// Converte os dados para JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Printf("Erro ao converter dados para JSON: %v\n", err)
		return
	}

	// Cria a requisição HTTP
	req, err := http.NewRequest("POST", elasticURL, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Erro ao criar requisição HTTP: %v\n", err)
		return
	}

	// Define os headers e a autenticação
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(authUser, authPassword)

	// Ignora a verificação do certificado TLS
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// Envia a requisição
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Erro ao enviar dados para Elasticsearch: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Lê a resposta
	bodyBytes, _ := io.ReadAll(resp.Body)
	fmt.Printf("Resposta do Elasticsearch: %s\n", string(bodyBytes))
}

func main() {
	parse()
}
