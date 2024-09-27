#SQS
export DEBUG=true
export AZURE_PROWLER_QUEUE_NAME="azure-prowler"
export AZURE_PROWLER_QUEUE_URL="http://localhost:9324/queue/azure-prowler"

export SQS_ENDPOINT="http://localhost:9324"

# GRPC
export CORE_SVC_ADDR="localhost:8080"
export DATA_SOURCE_API_SVC_ADDR="localhost:8081"

# Azure Permissions
export AZURE_CLIENT_ID="your_client_id"
export AZURE_TENANT_ID="your_tenant_id"
export AZURE_CLIENT_SECRET="your_client_secret"
