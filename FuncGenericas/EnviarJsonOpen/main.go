package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	opensearch "github.com/opensearch-project/opensearch-go"
)

// Exemplo de uso:
// ./enviar_json -endpoint=https://seu-servidor-opensearch.com:9200/seu_indice/_doc -json=seu_arquivo.json -username=seu_usuario -password=sua_senha -insecure

func main() {
	// Define as flags de linha de comando
	endpoint := flag.String("endpoint", "", "Endpoint do OpenSearch")
	jsonFile := flag.String("json", "", "Caminho para o arquivo JSON a ser enviado")
	username := flag.String("username", "", "Nome de usuário para autenticação")
	password := flag.String("password", "", "Senha para autenticação")
	insecure := flag.Bool("insecure", false, "Ignorar verificação de certificado SSL/TLS")

	flag.Parse()

	if *endpoint == "" || *jsonFile == "" {
		fmt.Println("Por favor, especifique o endpoint e o arquivo JSON: -endpoint=<endpoint> -json=<arquivo.json>")
		os.Exit(1)
	}

	// Configuração do cliente OpenSearch
	cfg := opensearch.Config{
		Addresses: []string{
			*endpoint,
		},
		Username: *username,
		Password: *password,
	}

	if *insecure {
		// Configura o transporte para ignorar verificação de certificado
		cfg.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	}

	// Inicializa o cliente OpenSearch
	client, err := opensearch.NewClient(cfg)
	if err != nil {
		log.Fatalf("Erro ao criar o cliente: %s", err)
	}

	// Chama a função para enviar o JSON
	err = sendJSONToOpenSearch(client, *endpoint, *jsonFile)
	if err != nil {
		log.Fatalf("Erro ao enviar o JSON: %s", err)
	} else {
		fmt.Println("JSON enviado com sucesso.")
	}
}

// Função para enviar um JSON para o OpenSearch
func sendJSONToOpenSearch(client *opensearch.Client, endpoint string, jsonFile string) error {
	// Lê o arquivo JSON
	jsonData, err := os.ReadFile(jsonFile)
	if err != nil {
		return fmt.Errorf("falha ao ler o arquivo JSON: %w", err)
	}

	// Cria uma nova requisição HTTP
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("falha ao criar a requisição HTTP: %w", err)
	}

	// Define o tipo de conteúdo como JSON
	req.Header.Set("Content-Type", "application/json")

	// Usa o transporte do cliente OpenSearch para enviar a requisição
	res, err := client.Transport.Perform(req)
	if err != nil {
		return fmt.Errorf("falha ao enviar a requisição: %w", err)
	}
	defer res.Body.Close()

	// Verifica se houve erro na resposta
	if res.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(res.Body)
		return fmt.Errorf("erro na resposta do servidor: %s", string(bodyBytes))
	}

	return nil
}
