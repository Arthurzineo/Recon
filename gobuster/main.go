package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
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
	subdomain     string
	ip            string
	sistema       string
	networkProto  string
	serverPort    string
	headers       map[string]string
	elasticURL    string
	authUser      string
	authPassword  string
	scanner       string
	x             string
	containerName string
	result        []string
	hora          string

	// Cliente HTTP global com timeout
	httpClient = &http.Client{
		Timeout: 10 * time.Second, // Define o timeout desejado
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
)

func init() {
	// Verifica se os argumentos necessários foram fornecidos
	if len(os.Args) < 7 {
		fmt.Println("Uso: programa <target> <subdomain> <ip> <sistema> <network.protocol> <server.port>")
		os.Exit(1)
	}

	// Recebe os argumentos da linha de comando
	target = os.Args[1]
	subdomain = os.Args[2]
	ip = os.Args[3]
	sistema = os.Args[4]
	networkProto = os.Args[5]
	serverPort = os.Args[6]

	// Define as variáveis necessárias
	elasticURL = fmt.Sprintf("https://localhost:9200/%s-webenum/_doc?refresh", target)
	authUser = "admin"
	authPassword = "StrongAdmin123!"
	scanner = "gobuster"
	hora = time.Now().Format(time.RFC3339)

	// Gera um UUID e extrai a primeira parte
	xUUID := uuid.New().String()
	x = strings.Split(xUUID, "-")[0]

	// Monta o nome do contêiner
	containerName = fmt.Sprintf("%s-%s-gobuster", target, x)

	// Define os headers
	headers = map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}
}

// Função para remover todas as sequências de escape ANSI
func removeAllANSIEscapeSequences(input string) string {
	// Regex para corresponder a todas as sequências de escape ANSI
	ansi := regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)
	return ansi.ReplaceAllString(input, "")
}

func executa() (string, error) {
	// Construir o caminho do volume usando a variável global 'target'
	volume := fmt.Sprintf("/c/recon:/scripts")

	// Escolha a imagem correta: use 'kali-recon-gobuster'
	image := "kali-recon"

	// Monta os argumentos do comando
	args := []string{
		"run",
		"--rm",
		"--name",
		containerName,
		"-v",
		volume, // Usa o caminho do volume dinâmico
		image,  // Use a imagem personalizada que inclui o gobuster
		"gobuster",
		"dir",
		"-u",
		sistema,
		"-w",
		"/scripts/common.txt",
		"--no-progress", // Adiciona a flag para desabilitar a barra de progresso
		"--no-color",
		"-q", // Adiciona a flag para desabilitar a colorização
	}

	// Para depuração
	fmt.Println("Comando sendo executado:")
	fmt.Println("docker", strings.Join(args, " "))

	// Executa o comando e captura a saída
	cmd := exec.Command("docker", args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	fmt.Println("Executando o contêiner Docker...")

	err := cmd.Run()
	if err != nil {
		fmt.Printf("Erro ao executar o comando: %v\n", err)
		fmt.Printf("Saída do comando (stderr):\n%s\n", stderr.String())
		return "", err
	}

	fmt.Println("Contêiner Docker executado com sucesso.")
	return stdout.String(), nil
}

func parse() {
	output, err := executa()
	if err != nil {
		fmt.Println("Falha na execução do `gobuster`.")
		return
	}

	if strings.TrimSpace(output) == "" {
		fmt.Println("Nenhum resultado obtido do gobuster.")
		return
	}

	fmt.Println("Saída do gobuster:")
	fmt.Println(output) // Log para verificar a saída capturada

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Remover a sequência específica '←[2K'
		line = strings.ReplaceAll(line, "←[2K", "")

		// Remover todas as sequências de escape ANSI restantes
		line = removeAllANSIEscapeSequences(line)

		// Remover tudo antes da primeira '/'
		idx := strings.Index(line, "/")
		if idx == -1 {
			fmt.Printf("Linha ignorada (não contém '/'): %s\n", line)
			continue
		}
		line = line[idx:]

		// Agora, a linha começa com '/'
		// Exemplo: "/admin                (Status: 301) [Size: 326] [--> http://businesscorp.com.br/admin/]"

		// Extrair o URLPath
		spaceIdx := strings.Index(line, " ")
		if spaceIdx == -1 {
			fmt.Printf("Linha ignorada (não contém espaços): %s\n", line)
			continue
		}
		urlPath := line[:spaceIdx]

		// Extrair o Status Code
		statusIdx := strings.Index(line, "(Status:")
		if statusIdx == -1 {
			fmt.Printf("Linha ignorada (não contém status): %s\n", line)
			continue
		}

		// Extrair o código numérico após "(Status:"
		statusStart := statusIdx + len("(Status:")
		statusEnd := strings.Index(line[statusStart:], ")")
		if statusEnd == -1 {
			fmt.Printf("Linha ignorada (não contém fechamento de status): %s\n", line)
			continue
		}

		statusCodeStr := strings.TrimSpace(line[statusStart : statusStart+statusEnd])
		statusCodeInt, err := strconv.ParseInt(statusCodeStr, 10, 64)
		if err != nil {
			fmt.Printf("Erro ao converter status code: %v\n", err)
			continue
		}

		fmt.Printf("Linha correspondida: %s, Status Code: %d\n", urlPath, statusCodeInt)

		// Constrói a estrutura WebEnum
		data := WebEnum{
			Timestamp:                  time.Now(),
			ServerAddress:              subdomain,
			ServerDomain:               subdomain,
			ServerIP:                   ip,
			ServerPort:                 parseInt64(serverPort),
			NetworkProtocol:            networkProto,
			URLPath:                    urlPath,
			HTTPResponseStatusCode:     statusCodeInt,
			URLOriginal:                sistema,
			URLFull:                    sistema + urlPath,
			VulnerabilityScannerVendor: scanner,
		}

		// Envia os dados para o Elasticsearch
		sendToElastic(data)
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

	fmt.Printf("Dados a serem enviados para Elasticsearch: %s\n", string(jsonData)) // Log adicionado

	// Cria um contexto com timeout de 10 segundos
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Cria a requisição HTTP com o contexto
	req, err := http.NewRequestWithContext(ctx, "POST", elasticURL, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Erro ao criar requisição HTTP: %v\n", err)
		return
	}

	// Define os headers e a autenticação
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(authUser, authPassword)

	fmt.Println("Enviando dados para Elasticsearch...") // Log adicionado

	// Envia a requisição utilizando o cliente HTTP global
	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Printf("Erro ao enviar dados para Elasticsearch: %v\n", err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("Dados enviados para Elasticsearch.") // Log adicionado

	// Lê a resposta
	bodyBytes, _ := io.ReadAll(resp.Body)
	fmt.Printf("Resposta do Elasticsearch: %s\n", string(bodyBytes))
}

func main() {
	parse()
}
