curl -XDELETE --insecure --user admin:'83d875fc-8789-11ec-9757-00505642c2bf' https://localhost:9200/$1-subdomain
echo
curl -XDELETE --insecure --user admin:'83d875fc-8789-11ec-9757-00505642c2bf' https://localhost:9200/$1-portscan
echo
curl -XDELETE --insecure --user admin:'83d875fc-8789-11ec-9757-00505642c2bf' https://localhost:9200/$1-webenum
echo
curl -XDELETE --insecure --user admin:'83d875fc-8789-11ec-9757-00505642c2bf' https://localhost:9200/$1-webvuln
echo
curl -XDELETE --insecure --user admin:'83d875fc-8789-11ec-9757-00505642c2bf' https://localhost:9200/$1-infravuln
