package prowler

const (
	// Azure Category
	CategoryAKS         = "aks"
	CategoryApp         = "app"
	CategoryAppInsights = "appinsights"
	CategoryCosmosDB    = "cosmosdb"
	CategoryDefender    = "defender"
	CategoryEntra       = "entra"
	CategoryIAM         = "iam"
	CategoryKeyVault    = "keyvault"
	CategoryMonitor     = "monitor"
	CategoryMySQL       = "mysql"
	CategoryNetwork     = "network"
	CategoryPolicy      = "policy"
	CategoryPostgreSQL  = "postgresql"
	CategorySQLServer   = "sqlserver"
	CategoryStorage     = "storage"
	CategoryVM          = "vm"

	scoreCritical = 0.8
	scoreHigh     = 0.6
	scoreMedium   = 0.4
	scoreLow      = 0.3
	scoreInfo     = 0.1
)

type recommend struct {
	Risk           string `json:"risk,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
}

type pluginMetaData struct {
	Score     float32
	Recommend recommend
	Tag       []string
}

// pluginMap maps azure plugin meta data.
// key: `{Categor}/{Plugin}`, value: meta
var pluginMap = map[string]pluginMetaData{
	CategoryAKS + "/aks_cluster_rbac_enabled": {
		Score: scoreMedium,
		Tag:   []string{"Microsoft.ContainerService/ManagedClusters"},
		Recommend: recommend{
			Risk:           "Kubernetes RBAC and AKS help you secure your cluster access and provide only the minimum required permissions to developers and operators.",
			Recommendation: "https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v2-privileged-access#pa-7-follow-just-enough-administration-least-privilege-principle",
		},
	},
	CategoryAKS + "/aks_clusters_created_with_private_nodes": {
		Score: scoreHigh,
		Tag:   []string{"Microsoft.ContainerService/ManagedClusters"},
		Recommend: recommend{
			Risk:           "Disabling public IP addresses on cluster nodes restricts access to only internal networks, forcing attackers to obtain local network access before attempting to compromise the underlying Kubernetes hosts.",
			Recommendation: "https://learn.microsoft.com/en-us/azure/aks/access-private-cluster",
		},
	},
	CategoryAKS + "/aks_clusters_public_access_disabled": {
		Score: scoreHigh,
		Tag:   []string{"Microsoft.ContainerService/ManagedClusters"},
		Recommend: recommend{
			Risk:           "In a private cluster, the master node has two endpoints, a private and public endpoint. The private endpoint is the internal IP address of the master, behind an internal load balancer in the master's wirtual network. Nodes communicate with the master using the private endpoint. The public endpoint enables the Kubernetes API to be accessed from outside the master's virtual network. Although Kubernetes API requires an authorized token to perform sensitive actions, a vulnerability could potentially expose the Kubernetes publically with unrestricted access. Additionally, an attacker may be able to identify the current cluster and Kubernetes API version and determine whether it is vulnerable to an attack. Unless required, disabling public endpoint will help prevent such threats, and require the attacker to be on the master's virtual network to perform any attack on the Kubernetes API.",
			Recommendation: "To use a private endpoint, create a new private endpoint in your virtual network then create a link between your virtual network and a new private DNS zone\n- https://learn.microsoft.com/en-us/azure/aks/access-private-cluster?tabs=azure-cli",
		},
	},
	CategoryAKS + "/aks_network_policy_enabled": {
		Score: scoreMedium,
		Tag:   []string{"Microsoft.ContainerService/managedClusters"},
		Recommend: recommend{
			Risk:           "All pods in an AKS cluster can send and receive traffic without limitations, by default. To improve security, you can define rules that control the flow of traffic. Back-end applications are often only exposed to required front-end services, for example. Or, database components are only accessible to the application tiers that connect to them. Network Policy is a Kubernetes specification that defines access policies for communication between Pods. Using Network Policies, you define an ordered set of rules to send and receive traffic and apply them to a collection of pods that match one or more label selectors. These network policy rules are defined as YAML manifests. Network policies can be included as part of a wider manifest that also creates a deployment or service.",
			Recommendation: "https://learn.microsoft.com/en-us/azure/aks/use-network-policies",
		},
	},
	CategoryApp + "/app_client_certificates_on": {
		Score: scoreMedium,
		Tag:   []string{"Microsoft.Web/sites/config"},
		Recommend: recommend{
			Risk:           "The TLS mutual authentication technique in enterprise environments ensures the authenticity of clients to the server. If incoming client certificates are enabled, then only an authenticated client who has valid certificates can access the app.",
			Recommendation: "1. Login to Azure Portal using https://portal.azure.com 2. Go to App Services 3. Click on each App 4. Under the Settings section, Click on Configuration, then General settings 5. Set the option Client certificate mode located under Incoming client certificates to Require\n- https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-4-authenticate-server-and-services",
		},
	},
	CategoryApp + "/app_ensure_auth_is_set_up": {
		Score: scoreMedium,
		Tag:   []string{"Microsoft.Web/sites"},
		Recommend: recommend{
			Risk:           "By Enabling App Service Authentication, every incoming HTTP request passes through it before being handled by the application code. It also handles authentication of users with the specified provider (Azure Active Directory, Facebook, Google, Microsoft Account, and Twitter), validation, storing and refreshing of tokens, managing the authenticated sessions and injecting identity information into request headers.",
			Recommendation: "1. Login to Azure Portal using https://portal.azure.com 2. Go to App Services 3. Click on each App 4. Under Setting section, click on Authentication 5. If no identity providers are set up, then click Add identity provider 6. Choose other parameters as per your requirements and click on Add\n- https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#website-contributor",
		},
	},
	CategoryApp + "/app_ensure_http_is_redirected_to_https": {
		Score: scoreMedium,
		Tag:   []string{"Microsoft.Web/sites/config"},
		Recommend: recommend{
			Risk:           "Enabling HTTPS-only traffic will redirect all non-secure HTTP requests to HTTPS ports. HTTPS uses the TLS/SSL protocol to provide a secure connection which is both encrypted and authenticated. It is therefore important to support HTTPS for the security benefits.",
			Recommendation: "1. Login to Azure Portal using https://portal.azure.com 2. Go to App Services 3. Click on each App 4. Under Setting section, Click on Configuration 5. In the General Settings section, set the HTTPS Only to On 6. Click Save\n- https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-data-protection#dp-3-encrypt-sensitive-data-in-transit",
		},
	},
	CategoryApp + "/app_ensure_java_version_is_latest": {
		Score: scoreLow,
		Tag:   []string{"Microsoft.Web/sites"},
		Recommend: recommend{
			Risk:           "Newer versions may contain security enhancements and additional functionality. Using the latest software version is recommended in order to take advantage of enhancements and new capabilities. With each software installation, organizations need to determine if a given update meets their requirements. They must also verify the compatibility and support provided for any additional software against the update revision that is selected.",
			Recommendation: "1. Login to Azure Portal using https://portal.azure.com 2. Go to App Services 3. Click on each App 4. Under Settings section, click on Configuration 5. Click on the General settings pane and ensure that for a Stack of Java the Major Version and Minor Version reflect the latest stable and supported release, and that the Java web server version is set to the auto-update option. NOTE: No action is required if Java version is set to Off, as Java is not used by your web app.\n- https://learn.microsoft.com/en-us/azure/app-service/configure-language-java?pivots=platform-linux#choosing-a-java-runtime-version",
		},
	},
	CategoryApp + "/app_ensure_php_version_is_latest": {
		Score: scoreLow,
		Tag:   []string{"Microsoft.Web/sites"},
		Recommend: recommend{
			Risk:           "Newer versions may contain security enhancements and additional functionality. Using the latest software version is recommended in order to take advantage of enhancements and new capabilities. With each software installation, organizations need to determine if a given update meets their requirements. They must also verify the compatibility and support provided for any additional software against the update revision that is selected.",
			Recommendation: "1. From Azure Home open the Portal Menu in the top left 2. Go to App Services 3. Click on each App 4. Under Settings section, click on Configuration 5. Click on the General settings pane, ensure that for a Stack of PHP the Major Version and Minor Version reflect the latest stable and supported release. NOTE: No action is required If PHP version is set to Off or is set with an empty value as PHP is not used by your web app\n- https://learn.microsoft.com/en-us/azure/app-service/configure-language-php?pivots=platform-linux#set-php-version",
		},
	},
	CategoryApp + "/app_ensure_python_version_is_latest": {
		Score: scoreLow,
		Tag:   []string{"Microsoft.Web/sites"},
		Recommend: recommend{
			Risk:           "Newer versions may contain security enhancements and additional functionality. Using the latest software version is recommended in order to take advantage of enhancements and new capabilities. With each software installation, organizations need to determine if a given update meets their requirements. They must also verify the compatibility and support provided for any additional software against the update revision that is selected. Using the latest full version will keep your stack secure to vulnerabilities and exploits.",
			Recommendation: "From Azure Portal 1. From Azure Home open the Portal Menu in the top left 2. Go to App Services 3. Click on each App 4. Under Settings section, click on Configuration 5. Click on the General settings pane and ensure that the Major Version and the Minor Version is set to the latest stable version available (Python 3.11, at the time of writing) NOTE: No action is required if Python version is set to Off, as Python is not used by your web app.\n- https://learn.microsoft.com/en-us/azure/app-service/configure-language-python#configure-python-version",
		},
	},
	CategoryApp + "/app_ensure_using_http20": {
		Score: scoreLow,
		Tag:   []string{"Microsoft.Web/sites"},
		Recommend: recommend{
			Risk:           "Newer versions may contain security enhancements and additional functionality. Using the latest version is recommended in order to take advantage of enhancements and new capabilities. With each software installation, organizations need to determine if a given update meets their requirements. They must also verify the compatibility and support provided for any additional software against the update revision that is selected. HTTP 2.0 has additional performance improvements on the head-of-line blocking problem of old HTTP version, header compression, and prioritization of requests. HTTP 2.0 no longer supports HTTP 1.1's chunked transfer encoding mechanism, as it provides its own, more efficient, mechanisms for data streaming.",
			Recommendation: "1. Login to Azure Portal using https://portal.azure.com 2. Go to App Services 3. Click on each App 4. Under Setting section, Click on Configuration 5. Set HTTP version to 2.0 under General settings\n- https://azure.microsoft.com/en-us/blog/announcing-http-2-support-in-azure-app-service/",
		},
	},
	CategoryApp + "/app_ftp_deployment_disabled": {
		Score: scoreMedium,
		Tag:   []string{"Microsoft.Web/sites/config"},
		Recommend: recommend{
			Risk:           "Azure FTP deployment endpoints are public. An attacker listening to traffic on a wifi network used by a remote employee or a corporate network could see login traffic in clear-text which would then grant them full control of the code base of the app or service. This finding is more severe if User Credentials for deployment are set at the subscription level rather than using the default Application Credentials which are unique per App.",
			Recommendation: "1. Go to the Azure Portal 2. Select App Services 3. Click on an app 4. Select Settings and then Configuration 5. Under General Settings, for the Platform Settings, the FTP state should be set to Disabled or FTPS Only\n- ",
		},
	},
	CategoryApp + "/app_function_access_keys_configured": {
		Score: scoreHigh,
		Tag:   []string{"function", "Microsoft.Web/sites"},
		Recommend: recommend{
			Risk:           "Unprotected function endpoints may be vulnerable to unauthorized access, leading to potential data breaches or malicious activity.",
			Recommendation: "Use access keys to secure Azure Functions. You can create and manage keys in the Azure portal or using the Azure CLI. For more information, see the official documentation.\n- https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts?tabs=v4#function-access-keys",
		},
	},
	CategoryApp + "/app_function_application_insights_enabled": {
		Score: scoreHigh,
		Tag:   []string{"function", "Microsoft.Web/sites"},
		Recommend: recommend{
			Risk:           "Without Application Insights, you may miss critical errors, performance degradation, or abnormal behavior in your Function App, potentially impacting availability and user experience.",
			Recommendation: "Enable Application Insights for your Azure Function App to monitor its performance and health.\n- https://learn.microsoft.com/en-us/azure/azure-monitor/app/monitor-functions",
		},
	},
	CategoryApp + "/app_function_ftps_deployment_disabled": {
		Score: scoreMedium,
		Tag:   []string{"function", "Microsoft.Web/sites"},
		Recommend: recommend{
			Risk:           "If left enabled, attackers can intercept network traffic and gain full control of the app or service, leading to potential data breaches and unauthorized modifications.",
			Recommendation: "It is recommended to disable FTP and FTPS deployments for Azure Functions to mitigate security risks. Instead, consider using more secure deployment methods such as Docker contianer or enabling continuous deployment with GitHub Actions.\n- https://learn.microsoft.com/en-us/azure/azure-functions/functions-deployment-technologies?tabs=windows#trigger-syncing",
		},
	},
	CategoryApp + "/app_function_identity_is_configured": {
		Score: scoreMedium,
		Tag:   []string{"function", "Microsoft.Web/sites"},
		Recommend: recommend{
			Risk:           "Not using managed identities can lead to less secure authentication and authorization practices, potentially exposing sensitive data.",
			Recommendation: "It is recommended to enable managed identities for Azure Functions to enhance security and access control. This allows the function app to easily access other Azure resources securely and with the appropriate permissions.\n- https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity",
		},
	},
	CategoryApp + "/app_function_identity_without_admin_privileges": {
		Score: scoreHigh,
		Tag:   []string{"function", "Microsoft.Web/sites"},
		Recommend: recommend{
			Risk:           "If Azure functions are configured with administrative privileges, it increases the risk of unauthorized access, privilege escalation, and data breaches. Attackers can exploit these privileges to gain access to sensitive data and compromise the entire system.",
			Recommendation: "To remediate this issue, ensure that Azure functions are not configured with an identity that has administrative privileges. Instead, use the principle of least privilege to grant only the necessary permissions to Azure functions. For more information, refer to the official documentation: Use the principle of least privilege.\n- https://docs.microsoft.com/en-us/azure/architecture/framework/security/design-identity-authorization#use-the-principle-of-least-privilege",
		},
	},
	CategoryApp + "/app_function_latest_runtime_version": {
		Score: scoreHigh,
		Tag:   []string{"function", "Microsoft.Web/sites"},
		Recommend: recommend{
			Risk:           "Using outdated runtime versions may introduce security risks and performance degradation. Outdated runtimes may have unpatched vulnerabilities, making them susceptible to attacks.",
			Recommendation: "https://learn.microsoft.com/en-us/azure/azure-functions/migrate-version-3-version-4?tabs=net8%2Cazure-cli%2Cwindows&pivots=programming-language-python",
		},
	},
	CategoryApp + "/app_function_not_publicly_accessible": {
		Score: scoreHigh,
		Tag:   []string{"function", "Microsoft.Web/sites"},
		Recommend: recommend{
			Risk:           "Exposing Azure Functions to the public internet increases the risk of unauthorized access, data breaches, and other security threats.",
			Recommendation: "Review the Azure Functions security guidelines and ensure that access restrictions are in place. Use Azure Private Link and Key Vault for enhanced security.\n- https://learn.microsoft.com/en-us/azure/app-service/overview-access-restrictions",
		},
	},
	CategoryApp + "/app_function_vnet_integration_enabled": {
		Score: scoreHigh,
		Tag:   []string{"function", "Microsoft.Web/sites"},
		Recommend: recommend{
			Risk:           "Without Virtual Network Integration, your Function Apps may be exposed to the public internet, increasing the risk of unauthorized access and potential security breaches.",
			Recommendation: "It is recommended to enable Virtual Network Integration for Azure Functions to enhance security and protect against unauthorized access.\n- https://docs.microsoft.com/en-us/azure/azure-functions/functions-networking-options#enable-virtual-network-integration",
		},
	},
	CategoryApp + "/app_http_logs_enabled": {
		Score: scoreLow,
		Tag:   []string{"Microsoft.Web/sites/config"},
		Recommend: recommend{
			Risk:           "Capturing web requests can be important supporting information for security analysts performing monitoring and incident response activities. Once logging, these logs can be ingested into SIEM or other central aggregation point for the organization.",
			Recommendation: "1. Go to App Services For each App Service: 2. Go to Diagnostic Settings 3. Click Add Diagnostic Setting 4. Check the checkbox next to 'HTTP logs' 5. Configure a destination based on your specific logging consumption capability (for example Stream to an event hub and then consuming with SIEM integration for Event Hub logging).\n- https://docs.microsoft.com/en-us/azure/app-service/troubleshoot-diagnostic-logs",
		},
	},
	CategoryApp + "/app_minimum_tls_version_12": {
		Score: scoreHigh,
		Tag:   []string{"Microsoft.Web/sites/config"},
		Recommend: recommend{
			Risk:           "App service currently allows the web app to set TLS versions 1.0, 1.1 and 1.2. It is highly recommended to use the latest TLS 1.2 version for web app secure connections.",
			Recommendation: "1. Login to Azure Portal using https://portal.azure.com 2. Go to App Services 3. Click on each App 4. Under Setting section, Click on TLS/SSL settings 5. Under the Bindings pane, ensure that Minimum TLS Version set to 1.2 under Protocol Settings\n- https://docs.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-data-protection#dp-3-encrypt-sensitive-data-in-transit",
		},
	},
	CategoryApp + "/app_register_with_identity": {
		Score: scoreMedium,
		Tag:   []string{"Microsoft.Web/sites"},
		Recommend: recommend{
			Risk:           "App Service provides a highly scalable, self-patching web hosting service in Azure. It also provides a managed identity for apps, which is a turn-key solution for securing access to Azure SQL Database and other Azure services.",
			Recommendation: "1. Login to Azure Portal using https://portal.azure.com 2. Go to App Services 3. Click on each App 4. Under Setting section, Click on Identity 5. Under the System assigned pane, set Status to On\n- https://learn.microsoft.com/en-us/azure/app-service/scenario-secure-app-authentication-app-service",
		},
	},
	CategoryAppInsights + "/appinsights_ensure_is_configured": {
		Score: scoreLow,
		Tag:   []string{"Microsoft.Insights/components"},
		Recommend: recommend{
			Risk:           "Configuring Application Insights provides additional data not found elsewhere within Azure as part of a much larger logging and monitoring program within an organization's Information Security practice. The types and contents of these logs will act as both a potential cost saving measure (application performance) and a means to potentially confirm the source of a potential incident (trace logging). Metrics and Telemetry data provide organizations with a proactive approach to cost savings by monitoring an application's performance, while the trace logging data provides necessary details in a reactive incident response scenario by helping organizations identify the potential source of an incident within their application.",
			Recommendation: "1. Navigate to Application Insights 2. Under the Basics tab within the PROJECT DETAILS section, select the Subscription 3. Select the Resource group 4. Within the INSTANCE DETAILS, enter a Name 5. Select a Region 6. Next to Resource Mode, select Workspace-based 7. Within the WORKSPACE DETAILS, select the Subscription for the log analytics workspace 8. Select the appropriate Log Analytics Workspace 9. Click Next:Tags > 10. Enter the appropriate Tags as Name, Value pairs. 11. Click Next:Review+Create 12. Click Create.\n- ",
		},
	},
	CategoryCosmosDB + "/cosmosdb_account_firewall_use_selected_networks": {
		Score: scoreMedium,
		Tag:   []string{"CosmosDB"},
		Recommend: recommend{
			Risk:           "Selecting certain networks for your Cosmos DB to communicate restricts the number of networks including the internet that can interact with what is stored within the database.",
			Recommendation: "1. Open the portal menu. 2. Select the Azure Cosmos DB blade. 3. Select a Cosmos DB account to audit. 4. Select Networking. 5. Under Public network access, select Selected networks. 6. Under Virtual networks, select + Add existing virtual network or + Add a new virtual network. 7. For existing networks, select subscription, virtual network, subnet and click Add. For new networks, provide a name, update the default values if required, and click Create. 8. Click Save.\n- https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security?tabs=azure-portal",
		},
	},
	CategoryCosmosDB + "/cosmosdb_account_use_aad_and_rbac": {
		Score: scoreMedium,
		Tag:   []string{"CosmosDB"},
		Recommend: recommend{
			Risk:           "AAD client authentication is considerably more secure than token-based authentication because the tokens must be persistent at the client. AAD does not require this.",
			Recommendation: "Map all the resources that currently access to the Azure Cosmos DB account with keys or access tokens. Create an Azure Active Directory (AAD) identity for each of these resources: For Azure resources, you can create a managed identity . You may choose between system-assigned and user-assigned managed identities. For non-Azure resources, create an AAD identity. Grant each AAD identity the minimum permission it requires. When possible, we recommend you use one of the 2 built-in role definitions: Cosmos DB Built-in Data Reader or Cosmos DB Built-in Data Contributor. Validate that the new resource is functioning correctly. After new permissions are granted to identities, it may take a few hours until they propagate. When all resources are working correctly with the new identities, continue to the next step. You can use the az resource update powershell command: $cosmosdbname = 'cosmos-db-account-name' $resourcegroup = 'resource-group-name' $cosmosdb = az cosmosdb show --name $cosmosdbname --resource-group $resourcegroup | ConvertFrom-Json az resource update --ids $cosmosdb.id --set properties.disableLocalAuth=true --latest- include-preview\n- https://learn.microsoft.com/en-us/azure/cosmos-db/role-based-access-control",
		},
	},
	CategoryCosmosDB + "/cosmosdb_account_use_private_endpoints": {
		Score: scoreMedium,
		Tag:   []string{"CosmosDB"},
		Recommend: recommend{
			Risk:           "For sensitive data, private endpoints allow granular control of which services can communicate with Cosmos DB and ensure that this network traffic is private. You set this up on a case by case basis for each service you wish to be connected.",
			Recommendation: "1. Open the portal menu. 2. Select the Azure Cosmos DB blade. 3. Select the Azure Cosmos DB account. 4. Select Networking. 5. Select Private access. 6. Click + Private Endpoint. 7. Provide a Name. 8. Click Next. 9. From the Resource type drop down, select Microsoft.AzureCosmosDB/databaseAccounts. 10. From the Resource drop down, select the Cosmos DB account. 11. Click Next. 12. Provide appropriate Virtual Network details. 13. Click Next. 14. Provide appropriate DNS details. 15. Click Next. 16. Optionally provide Tags. 17. Click Next : Review + create. 18. Click Create.\n- https://docs.microsoft.com/en-us/azure/private-link/tutorial-private-endpoint-cosmosdb-portal",
		},
	},
	CategoryDefender + "/defender_additional_email_configured_with_a_security_contact": {
		Score: scoreMedium,
		Tag:   []string{"AzureEmailNotifications"},
		Recommend: recommend{
			Risk:           "Microsoft Defender for Cloud emails the Subscription Owner to notify them about security alerts. Adding your Security Contact's email address to the 'Additional email addresses' field ensures that your organization's Security Team is included in these alerts. This ensures that the proper people are aware of any potential compromise in order to mitigate the risk in a timely fashion.",
			Recommendation: "1. From Azure Home select the Portal Menu 2. Select Microsoft Defender for Cloud 3. Click on Environment Settings 4. Click on the appropriate Management Group, Subscription, or Workspace 5. Click on Email notifications 6. Enter a valid security contact email address (or multiple addresses separated by commas) in the Additional email addresses field 7. Click Save\n- https://learn.microsoft.com/en-us/rest/api/defenderforcloud/security-contacts/list?view=rest-defenderforcloud-2020-01-01-preview&tabs=HTTP",
		},
	},
	CategoryDefender + "/defender_assessments_vm_endpoint_protection_installed": {
		Score: scoreHigh,
		Tag:   []string{"Microsoft.Security/assessments"},
		Recommend: recommend{
			Risk:           "Installing endpoint protection systems (like anti-malware for Azure) provides for real-time protection capability that helps identify and remove viruses, spyware, and other malicious software. These also offer configurable alerts when known-malicious or unwanted software attempts to install itself or run on Azure systems.",
			Recommendation: "Follow Microsoft Azure documentation to install endpoint protection from the security center. Alternatively, you can employ your own endpoint protection tool for your OS.\n- ",
		},
	},
	CategoryDefender + "/defender_auto_provisioning_log_analytics_agent_vms_on": {
		Score: scoreMedium,
		Tag:   []string{"AzureDefenderPlan"},
		Recommend: recommend{
			Risk:           "Missing critical security information about your Azure VMs, such as security alerts, security recommendations, and change tracking.",
			Recommendation: "Ensure comprehensive visibility into possible security vulnerabilities, including missing updates, misconfigured operating system security settings, and active threats, allowing for timely mitigation and improved overall security posture\n- https://learn.microsoft.com/en-us/azure/defender-for-cloud/monitoring-components",
		},
	},
	CategoryDefender + "/defender_auto_provisioning_vulnerabilty_assessments_machines_on": {
		Score: scoreMedium,
		Tag:   []string{"AzureDefenderPlan"},
		Recommend: recommend{
			Risk:           "Vulnerability assessment for machines scans for various security-related configurations and events such as system updates, OS vulnerabilities, and endpoint protection, then produces alerts on threat and vulnerability findings.",
			Recommendation: "1. From Azure Home select the Portal Menu. 2. Select Microsoft Defender for Cloud. 3. Then Environment Settings. 4. Select a subscription. 5. Click on Settings & Monitoring. 6. Ensure that Vulnerability assessment for machines is set to On. Repeat this for any additional subscriptions.\n- ",
		},
	},
	CategoryDefender + "/defender_container_images_resolved_vulnerabilities": {
		Score: scoreMedium,
		Tag:   []string{"Microsoft.Security/assessments"},
		Recommend: recommend{
			Risk:           "If vulnerabilities are not resolved, attackers can exploit them to gain unauthorized access to your containerized applications and data.",
			Recommendation: "https://learn.microsoft.com/en-us/azure/container-registry/scan-images-defender",
		},
	},
	CategoryDefender + "/defender_container_images_scan_enabled": {
		Score: scoreMedium,
		Tag:   []string{"Microsoft.Security"},
		Recommend: recommend{
			Risk:           "Vulnerabilities in software packages can be exploited by hackers or malicious users to obtain unauthorized access to local cloud resources. Azure Defender and other third party products allow images to be scanned for known vulnerabilities.",
			Recommendation: "https://learn.microsoft.com/en-us/azure/container-registry/scan-images-defender",
		},
	},
	CategoryDefender + "/defender_ensure_defender_for_app_services_is_on": {
		Score: scoreHigh,
		Tag:   []string{"AzureDefenderPlan"},
		Recommend: recommend{
			Risk:           "Turning on Microsoft Defender for App Service enables threat detection for App Service, providing threat intelligence, anomaly detection, and behavior analytics in the Microsoft Defender for Cloud.",
			Recommendation: "By default, Microsoft Defender for Cloud is not enabled for your App Service instances. Enabling the Defender security service for App Service instances allows for advanced security defense using threat detection capabilities provided by Microsoft Security Response Center.\n- ",
		},
	},
	CategoryDefender + "/defender_ensure_defender_for_arm_is_on": {
		Score: scoreHigh,
		Tag:   []string{"AzureDefenderPlan"},
		Recommend: recommend{
			Risk:           "Scanning resource requests lets you be alerted every time there is suspicious activity in order to prevent a security threat from being introduced.",
			Recommendation: "Enable  Microsoft Defender for Azure Resource Manager\n- ",
		},
	},
	CategoryDefender + "/defender_ensure_defender_for_azure_sql_databases_is_on": {
		Score: scoreHigh,
		Tag:   []string{"AzureDefenderPlan"},
		Recommend: recommend{
			Risk:           "Turning on Microsoft Defender for Azure SQL Databases enables threat detection for Azure SQL database servers, providing threat intelligence, anomaly detection, and behavior analytics in the Microsoft Defender for Cloud.",
			Recommendation: "By default, Microsoft Defender for Cloud is disabled for all your SQL database servers. Defender for Cloud monitors your SQL database servers for threats such as SQL injection, brute-force attacks, and privilege abuse. The security service provides action-oriented security alerts with details of the suspicious activity and guidance on how to mitigate the security threats.\n- ",
		},
	},
	CategoryDefender + "/defender_ensure_defender_for_containers_is_on": {
		Score: scoreHigh,
		Tag:   []string{"AzureDefenderPlan"},
		Recommend: recommend{
			Risk:           "Ensure that Microsoft Defender for Cloud is enabled for all your Azure containers. Turning on the Defender for Cloud service enables threat detection for containers, providing threat intelligence, anomaly detection, and behavior analytics.",
			Recommendation: "By default, Microsoft Defender for Cloud is not enabled for your Azure cloud containers. Enabling the Defender security service for Azure containers allows for advanced security defense against threats, using threat detection capabilities provided by the Microsoft Security Response Center (MSRC).\n- ",
		},
	},
	CategoryDefender + "/defender_ensure_defender_for_cosmosdb_is_on": {
		Score: scoreHigh,
		Tag:   []string{"AzureDefenderPlan"},
		Recommend: recommend{
			Risk:           "In scanning Cosmos DB requests within a subscription, requests are compared to a heuristic list of potential security threats. These threats could be a result of a security breach within your services, thus scanning for them could prevent a potential security threat from being introduced.",
			Recommendation: "By default, Microsoft Defender for Cloud is not enabled for your App Service instances. Enabling the Defender security service for App Service instances allows for advanced security defense using threat detection capabilities provided by Microsoft Security Response Center.\n- Enable Microsoft Defender for Cosmos DB",
		},
	},
	CategoryDefender + "/defender_ensure_defender_for_databases_is_on": {
		Score: scoreHigh,
		Tag:   []string{"AzureDefenderPlan"},
		Recommend: recommend{
			Risk:           "Enabling Microsoft Defender for Azure SQL Databases allows your organization more granular control of the infrastructure running your database software",
			Recommendation: "Enable Microsoft Defender for Azure SQL Databases\n- ",
		},
	},
	CategoryDefender + "/defender_ensure_defender_for_dns_is_on": {
		Score: scoreHigh,
		Tag:   []string{"AzureDefenderPlan"},
		Recommend: recommend{
			Risk:           "DNS lookups within a subscription are scanned and compared to a dynamic list of websites that might be potential security threats. These threats could be a result of a security breach within your services, thus scanning for them could prevent a potential security threat from being introduced.",
			Recommendation: "By default, Microsoft Defender for Cloud is not enabled for your App Service instances. Enabling the Defender security service for App Service instances allows for advanced security defense using threat detection capabilities provided by Microsoft Security Response Center.\n- ",
		},
	},
	CategoryDefender + "/defender_ensure_defender_for_keyvault_is_on": {
		Score: scoreHigh,
		Tag:   []string{"AzureDefenderPlan"},
		Recommend: recommend{
			Risk:           "By default, Microsoft Defender for Cloud is disabled for Azure key vaults. Defender for Cloud detects unusual and potentially harmful attempts to access or exploit your Azure Key Vault data. This layer of protection allows you to address threats without being a security expert, and without the need to use and manage third-party security monitoring tools or services.",
			Recommendation: "Ensure that Microsoft Defender for Cloud is enabled for Azure key vaults. Key Vault is the Azure cloud service that safeguards encryption keys and secrets like certificates, connection-based strings, and passwords.\n- ",
		},
	},
	CategoryDefender + "/defender_ensure_defender_for_os_relational_databases_is_on": {
		Score: scoreHigh,
		Tag:   []string{"AzureDefenderPlan"},
		Recommend: recommend{
			Risk:           "Turning on Microsoft Defender for Open-source relational databases enables threat detection for Open-source relational databases, providing threat intelligence, anomaly detection, and behavior analytics in the Microsoft Defender for Cloud.",
			Recommendation: "Enabling Microsoft Defender for Open-source relational databases allows for greater defense-in-depth, with threat detection provided by the Microsoft Security Response Center (MSRC).\n- ",
		},
	},
	CategoryDefender + "/defender_ensure_defender_for_server_is_on": {
		Score: scoreHigh,
		Tag:   []string{"AzureDefenderPlan"},
		Recommend: recommend{
			Risk:           "Turning on Microsoft Defender for Servers enables threat detection for Servers, providing threat intelligence, anomaly detection, and behavior analytics in the Microsoft Defender for Cloud.",
			Recommendation: "Enabling Microsoft Defender for Cloud standard pricing tier allows for better security assessment with threat detection provided by the Microsoft Security Response Center (MSRC), advanced security policies, adaptive application control, network threat detection, and regulatory compliance management.\n- ",
		},
	},
	CategoryDefender + "/defender_ensure_defender_for_sql_servers_is_on": {
		Score: scoreHigh,
		Tag:   []string{"AzureDefenderPlan"},
		Recommend: recommend{
			Risk:           "Turning on Microsoft Defender for SQL servers on machines enables threat detection for SQL servers on machines, providing threat intelligence, anomaly detection, and behavior analytics in the Microsoft Defender for Cloud.",
			Recommendation: "By default, Microsoft Defender for Cloud is disabled for the Microsoft SQL servers running on virtual machines. Defender for Cloud for SQL Server virtual machines continuously monitors your SQL database servers for threats such as SQL injection, brute-force attacks, and privilege abuse. The security service provides security alerts together with details of the suspicious activity and guidance on how to mitigate to the security threats.\n- ",
		},
	},
	CategoryDefender + "/defender_ensure_defender_for_storage_is_on": {
		Score: scoreHigh,
		Tag:   []string{"AzureDefenderPlan"},
		Recommend: recommend{
			Risk:           "Ensure that Microsoft Defender for Cloud is enabled for your Microsoft Azure storage accounts. Defender for storage accounts is an Azure-native layer of security intelligence that detects unusual and potentially harmful attempts to access or exploit your Azure cloud storage accounts.",
			Recommendation: "By default, Microsoft Defender for Cloud is disabled for your storage accounts. Enabling the Defender security service for Azure storage accounts allows for advanced security defense using threat detection capabilities provided by the Microsoft Security Response Center (MSRC). MSRC investigates all reports of security vulnerabilities affecting Microsoft products and services, including Azure cloud services.\n- ",
		},
	},
	CategoryDefender + "/defender_ensure_iot_hub_defender_is_on": {
		Score: scoreHigh,
		Tag:   []string{"DefenderIoT"},
		Recommend: recommend{
			Risk:           "IoT devices are very rarely patched and can be potential attack vectors for enterprise networks. Updating their network configuration to use a central security hub allows for detection of these breaches.",
			Recommendation: "1. Go to IoT Hub. 2. Select a IoT Hub to validate. 3. Select Overview in Defender for IoT. 4. Click on Secure your IoT solution, and complete the onboarding.\n- https://learn.microsoft.com/en-us/azure/defender-for-iot/device-builders/quickstart-onboard-iot-hub",
		},
	},
	CategoryDefender + "/defender_ensure_mcas_is_enabled": {
		Score: scoreMedium,
		Tag:   []string{"DefenderSettings"},
		Recommend: recommend{
			Risk:           "Microsoft Defender for Cloud offers an additional layer of protection by using Azure Resource Manager events, which is considered to be the control plane for Azure. By analyzing the Azure Resource Manager records, Microsoft Defender for Cloud detects unusual or potentially harmful operations in the Azure subscription environment. Several of the preceding analytics are powered by Microsoft Defender for Cloud Apps. To benefit from these analytics, subscription must have a Cloud App Security license. Microsoft Defender for Cloud Apps works only with Standard Tier subscriptions.",
			Recommendation: "1. From Azure Home select the Portal Menu. 2. Select Microsoft Defender for Cloud. 3. Select Environment Settings blade. 4. Select the subscription. 5. Check App Service Defender Plan to On. 6. Select Save.\n- https://docs.microsoft.com/en-us/rest/api/securitycenter/settings/list",
		},
	},
	CategoryDefender + "/defender_ensure_notify_alerts_severity_is_high": {
		Score: scoreHigh,
		Tag:   []string{"AzureEmailNotifications"},
		Recommend: recommend{
			Risk:           "Microsoft Defender for Cloud emails the Subscription Owner to notify them about security alerts. Adding your Security Contact's email address to the 'Additional email addresses' field ensures that your organization's Security Team is included in these alerts. This ensures that the proper people are aware of any potential compromise in order to mitigate the risk in a timely fashion.",
			Recommendation: "1. From Azure Home select the Portal Menu 2. Select Microsoft Defender for Cloud 3. Click on Environment Settings 4. Click on the appropriate Management Group, Subscription, or Workspace 5. Click on Email notifications 6. Enter a valid security contact email address (or multiple addresses separated by commas) in the Additional email addresses field 7. Click Save\n- https://docs.microsoft.com/en-us/rest/api/securitycenter/securitycontacts/list",
		},
	},
	CategoryDefender + "/defender_ensure_notify_emails_to_owners": {
		Score: scoreMedium,
		Tag:   []string{"AzureEmailNotifications"},
		Recommend: recommend{
			Risk:           "Enabling security alert emails to subscription owners ensures that they receive security alert emails from Microsoft. This ensures that they are aware of any potential security issues and can mitigate the risk in a timely fashion.",
			Recommendation: "1. From Azure Home select the Portal Menu 2. Select Microsoft Defender for Cloud 3. Click on Environment Settings 4. Click on the appropriate Management Group, Subscription, or Workspace 5. Click on Email notifications 6. In the drop down of the All users with the following roles field select Owner 7. Click Save\n- https://docs.microsoft.com/en-us/rest/api/securitycenter/securitycontacts/list",
		},
	},
	CategoryDefender + "/defender_ensure_system_updates_are_applied": {
		Score: scoreHigh,
		Tag:   []string{"AzureDefenderRecommendation"},
		Recommend: recommend{
			Risk:           "The Azure Security Center retrieves a list of available security and critical updates from Windows Update or Windows Server Update Services (WSUS), depending on which service is configured on a Windows VM. The security center also checks for the latest updates in Linux systems. If a VM is missing a system update, the security center will recommend system updates be applied.",
			Recommendation: "Follow Microsoft Azure documentation to apply security patches from the security center. Alternatively, you can employ your own patch assessment and management tool to periodically assess, report, and install the required security patches for your OS.\n- https://learn.microsoft.com/en-us/azure/virtual-machines/updates-maintenance-overview",
		},
	},
	CategoryDefender + "/defender_ensure_wdatp_is_enabled": {
		Score: scoreMedium,
		Tag:   []string{"DefenderSettings"},
		Recommend: recommend{
			Risk:           "Microsoft Defender for Endpoint integration brings comprehensive Endpoint Detection and Response (EDR) capabilities within Microsoft Defender for Cloud. This integration helps to spot abnormalities, as well as detect and respond to advanced attacks on endpoints monitored by Microsoft Defender for Cloud. MDE works only with Standard Tier subscriptions.",
			Recommendation: "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/azure-server-integration?view=o365-worldwide",
		},
	},
	CategoryEntra + "/entra_conditional_access_policy_require_mfa_for_management_api": {
		Score: scoreMedium,
		Tag:   []string{"#microsoft.graph.conditionalAccess"},
		Recommend: recommend{
			Risk:           "Administrative access to the Windows Azure Service Management API should be secured with a higher level of scrutiny to authenticating mechanisms. Enabling multifactor authentication is recommended to reduce the potential for abuse of Administrative actions, and to prevent intruders or compromised admin credentials from changing administrative settings.",
			Recommendation: "1. From the Azure Admin Portal dashboard, open Microsoft Entra ID. 2. Click Security in the Entra ID blade. 3. Click Conditional Access in the Security blade. 4. Click Policies in the Conditional Access blade. 5. Click + New policy. 6. Enter a name for the policy. 7. Click the blue text under Users. 8. Under Include, select All users. 9. Under Exclude, check Users and groups. 10. Select users or groups to be exempted from this policy (e.g. break-glass emergency accounts, and non-interactive service accounts) then click the Select button. 11. Click the blue text under Target Resources. 12. Under Include, click the Select apps radio button. 13. Click the blue text under Select. 14. Check the box next to Windows Azure Service Management APIs then click the Select button. 15. Click the blue text under Grant. 16. Under Grant access check the box for Require multifactor authentication then click the Select button. 17. Before creating, set Enable policy to Report-only. 18. Click Create. After testing the policy in report-only mode, update the Enable policy setting from Report-only to On.\n- https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps",
		},
	},
	CategoryEntra + "/entra_global_admin_in_less_than_five_users": {
		Score: scoreHigh,
		Tag:   []string{"#microsoft.graph.directoryRole"},
		Recommend: recommend{
			Risk:           "The Global Administrator role has extensive privileges across all services in Microsoft Entra ID. The Global Administrator role should never be used in regular daily activities, administrators should have a regular user account for daily activities, and a separate account for administrative responsibilities. Limiting the number of Global Administrators helps mitigate the risk of unauthorized access, reduces the potential impact of human error, and aligns with the principle of least privilege to reduce the attack surface of an Azure tenant. Conversely, having at least two Global Administrators ensures that administrative functions can be performed without interruption in case of unavailability of a single admin.",
			Recommendation: "1. From Azure Home select the Portal Menu 2. Select Microsoft Entra ID 3. Select Roles and Administrators 4. Select Global Administrator 5. Ensure less than 5 users are actively assigned the role. 6. Ensure that at least 2 users are actively assigned the role.\n- https://learn.microsoft.com/en-us/microsoft-365/admin/add-users/about-admin-roles?view=o365-worldwide#security-guidelines-for-assigning-roles",
		},
	},
	CategoryEntra + "/entra_non_privileged_user_has_mfa": {
		Score: scoreHigh,
		Tag:   []string{"#microsoft.graph.users"},
		Recommend: recommend{
			Risk:           "Multi-factor authentication requires an individual to present a minimum of two separate forms of authentication before access is granted. Multi-factor authentication provides additional assurance that the individual attempting to gain access is who they claim to be. With multi-factor authentication, an attacker would need to compromise at least two different authentication mechanisms, increasing the difficulty of compromise and thus reducing the risk.",
			Recommendation: "Activate one of the available multi-factor authentication methods for users in Microsoft Entra ID.\n- https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-azure-mfa",
		},
	},
	CategoryEntra + "/entra_policy_default_users_cannot_create_security_groups": {
		Score: scoreHigh,
		Tag:   []string{"#microsoft.graph.authorizationPolicy"},
		Recommend: recommend{
			Risk:           "When creating security groups is enabled, all users in the directory are allowed to create new security groups and add members to those groups. Unless a business requires this day-to-day delegation, security group creation should be restricted to administrators only.",
			Recommendation: "1. From Azure Home select the Portal Menu 2. Select Microsoft Entra ID 3. Select Groups 4. Select General under Settings 5. Set Users can create security groups in Azure portals, API or PowerShell to No\n- ",
		},
	},
	CategoryEntra + "/entra_policy_ensure_default_user_cannot_create_apps": {
		Score: scoreHigh,
		Tag:   []string{"#microsoft.graph.authorizationPolicy"},
		Recommend: recommend{
			Risk:           "It is recommended to only allow an administrator to register custom-developed applications. This ensures that the application undergoes a formal security review and approval process prior to exposing Azure Active Directory data. Certain users like developers or other high-request users may also be delegated permissions to prevent them from waiting on an administrative user. Your organization should review your policies and decide your needs.",
			Recommendation: "1. From Azure Home select the Portal Menu 2. Select Azure Active Directory 3. Select Users 4. Select User settings 5. Ensure that Users can register applications is set to No\n- https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/delegate-app-roles#restrict-who-can-create-applications",
		},
	},
	CategoryEntra + "/entra_policy_ensure_default_user_cannot_create_tenants": {
		Score: scoreHigh,
		Tag:   []string{"#microsoft.graph.authorizationPolicy"},
		Recommend: recommend{
			Risk:           "It is recommended to only allow an administrator to create new tenants. This prevent users from creating new Azure AD or Azure AD B2C tenants and ensures that only authorized users are able to do so.",
			Recommendation: "1. From Azure Home select the Portal Menu 2. Select Azure Active Directory 3. Select Users 4. Select User settings 5. Set 'Restrict non-admin users from creating' tenants to 'Yes'\n- https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#tenant-creator",
		},
	},
	CategoryEntra + "/entra_policy_guest_invite_only_for_admin_roles": {
		Score: scoreMedium,
		Tag:   []string{"#microsoft.graph.authorizationPolicy"},
		Recommend: recommend{
			Risk:           "Restricting invitations to users with specific administrator roles ensures that only authorized accounts have access to cloud resources. This helps to maintain 'Need to Know' permissions and prevents inadvertent access to data. By default the setting Guest invite restrictions is set to Anyone in the organization can invite guest users including guests and non-admins. This would allow anyone within the organization to invite guests and non-admins to the tenant, posing a security risk.",
			Recommendation: "1. From Azure Home select the Portal Menu 2. Select Microsoft Entra ID 3. Then External Identities 4. Select External collaboration settings 5. Under Guest invite settings, for Guest invite restrictions, ensure that Only users assigned to specific admin roles can invite guest users is selected\n- https://learn.microsoft.com/en-us/answers/questions/685101/how-to-allow-only-admins-to-add-guests",
		},
	},
	CategoryEntra + "/entra_policy_guest_users_access_restrictions": {
		Score: scoreMedium,
		Tag:   []string{"#microsoft.graph.authorizationPolicy"},
		Recommend: recommend{
			Risk:           "Limiting guest access ensures that guest accounts do not have permission for certain directory tasks, such as enumerating users, groups or other directory resources, and cannot be assigned to administrative roles in your directory. Guest access has three levels of restriction. 1. Guest users have the same access as members (most inclusive), 2. Guest users have limited access to properties and memberships of directory objects (default value), 3. Guest user access is restricted to properties and memberships of their own directory objects (most restrictive). The recommended option is the 3rd, most restrictive: 'Guest user access is restricted to their own directory object'.",
			Recommendation: "1. From Azure Home select the Portal Menu 2. Select Microsoft Entra ID 3. Then External Identities 4. Select External collaboration settings 5. Under Guest user access, change Guest user access restrictions to be Guest user access is restricted to properties and memberships of their own directory objects\n- https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions#member-and-guest-users",
		},
	},
	CategoryEntra + "/entra_policy_restricts_user_consent_for_apps": {
		Score: scoreHigh,
		Tag:   []string{"#microsoft.graph.authorizationPolicy"},
		Recommend: recommend{
			Risk:           "If Microsoft Entra ID is running as an identity provider for third-party applications, permissions and consent should be limited to administrators or pre-approved. Malicious applications may attempt to exfiltrate data or abuse privileged user accounts.",
			Recommendation: "1. From Azure Home select the Portal Menu 2. Select Microsoft Entra ID 3. Select Enterprise Applications 4. Select Consent and permissions 5. Select User consent settings 6. Set User consent for applications to Do not allow user consent 7. Click save\n- https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users",
		},
	},
	CategoryEntra + "/entra_policy_user_consent_for_verified_apps": {
		Score: scoreHigh,
		Tag:   []string{"#microsoft.graph.authorizationPolicy"},
		Recommend: recommend{
			Risk:           "If Microsoft Entra ID is running as an identity provider for third-party applications, permissions and consent should be limited to administrators or pre-approved. Malicious applications may attempt to exfiltrate data or abuse privileged user accounts.",
			Recommendation: "1. From Azure Home select the Portal Menu 2. Select Microsoft Entra ID 3. Select Enterprise Applications 4. Select Consent and permissions 5. Select User consent settings 6. Under User consent for applications, select Allow user consent for apps from verified publishers, for selected permissions 7. Select Save\n- https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users",
		},
	},
	CategoryEntra + "/entra_privileged_user_has_mfa": {
		Score: scoreHigh,
		Tag:   []string{"#microsoft.graph.users"},
		Recommend: recommend{
			Risk:           "Multi-factor authentication requires an individual to present a minimum of two separate forms of authentication before access is granted. Multi-factor authentication provides additional assurance that the individual attempting to gain access is who they claim to be. With multi-factor authentication, an attacker would need to compromise at least two different authentication mechanisms, increasing the difficulty of compromise and thus reducing the risk.",
			Recommendation: "Activate one of the available multi-factor authentication methods for users in Microsoft Entra ID.\n- https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-azure-mfa",
		},
	},
	CategoryEntra + "/entra_security_defaults_enabled": {
		Score: scoreHigh,
		Tag:   []string{"#microsoft.graph.identitySecurityDefaultsEnforcementPolicy"},
		Recommend: recommend{
			Risk:           "Security defaults provide secure default settings that we manage on behalf of organizations to keep customers safe until they are ready to manage their own identity security settings. For example, doing the following: - Requiring all users and admins to register for MFA. - Challenging users with MFA - when necessary, based on factors such as location, device, role, and task. - Disabling authentication from legacy authentication clients, which can’t do MFA.",
			Recommendation: "1. From Azure Home select the Portal Menu. 2. Browse to Microsoft Entra ID > Properties 3. Select Manage security defaults 4. Set the Enable security defaults to Enabled 5. Select Save\n- https://techcommunity.microsoft.com/t5/microsoft-entra-blog/introducing-security-defaults/ba-p/1061414",
		},
	},
	CategoryEntra + "/entra_trusted_named_locations_exists": {
		Score: scoreMedium,
		Tag:   []string{"#microsoft.graph.ipNamedLocation"},
		Recommend: recommend{
			Risk:           "Defining trusted source IP addresses or ranges helps organizations create and enforce Conditional Access policies around those trusted or untrusted IP addresses and ranges. Users authenticating from trusted IP addresses and/or ranges may have less access restrictions or access requirements when compared to users that try to authenticate to Microsoft Entra ID from untrusted locations or untrusted source IP addresses/ranges.",
			Recommendation: "1. Navigate to the Microsoft Entra ID Conditional Access Blade 2. Click on the Named locations blade 3. Within the Named locations blade, click on IP ranges location 4. Enter a name for this location setting in the Name text box 5. Click on the + sign 6. Add an IP Address Range in CIDR notation inside the text box that appears 7. Click on the Add button 8. Repeat steps 5 through 7 for each IP Range that needs to be added 9. If the information entered are trusted ranges, select the Mark as trusted location check box 10. Once finished, click on Create\n- https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-7-restrict-resource-access-based-on--conditions",
		},
	},
	CategoryEntra + "/entra_user_with_vm_access_has_mfa": {
		Score: scoreMedium,
		Tag:   []string{"#microsoft.graph.users"},
		Recommend: recommend{
			Risk:           "Managed disks are by default encrypted on the underlying hardware, so no additional encryption is required for basic protection. It is available if additional encryption is required. Managed disks are by design more resilient that storage accounts. For ARM-deployed Virtual Machines, Azure Adviser will at some point recommend moving VHDs to managed disks both from a security and cost management perspective.",
			Recommendation: "1. Log in to the Azure portal. Reducing access of managed identities attached to virtual machines. 2. This can be remediated by enabling MFA for user, Removing user access or • Case I : Enable MFA for users having access on virtual machines. 1. Navigate to Azure AD from the left pane and select Users from the Manage section. 2. Click on Per-User MFA from the top menu options and select each user with MULTI-FACTOR AUTH STATUS as Disabled and can login to virtual machines:  From quick steps on the right side select enable.  Click on enable multi-factor auth and share the link with the user to setup MFA as required. • Case II : Removing user access on a virtual machine. 1. Select the Subscription, then click on Access control (IAM). 2. Select Role assignments and search for Virtual Machine Administrator Login or Virtual Machine User Login or any role that provides access to log into virtual machines. 3. Click on Role Name, Select Assignments, and remove identities with no MFA configured. • Case III : Reducing access of managed identities attached to virtual machines. 1. Select the Subscription, then click on Access control (IAM). 2. Select Role Assignments from the top menu and apply filters on Assignment type as Privileged administrator roles and Type as Virtual Machines. 3. Click on Role Name, Select Assignments, and remove identities access make sure this follows the least privileges principal.\n- ",
		},
	},
	CategoryEntra + "/entra_users_cannot_create_microsoft_365_groups": {
		Score: scoreHigh,
		Tag:   []string{"Microsoft.Users/Settings"},
		Recommend: recommend{
			Risk:           "Restricting Microsoft 365 group creation to administrators only ensures that creation of Microsoft 365 groups is controlled by the administrator. Appropriate groups should be created and managed by the administrator and group creation rights should not be delegated to any other user.",
			Recommendation: "1. From Azure Home select the Portal Menu 2. Select Microsoft Entra ID 3. Then Groups 4. Select General in settings 5. Set Users can create Microsoft 365 groups in Azure portals, API or PowerShell to No\n- https://learn.microsoft.com/en-us/microsoft-365/solutions/manage-creation-of-groups?view=o365-worldwide&redirectSourcePath=%252fen-us%252farticle%252fControl-who-can-create-Office-365-Groups-4c46c8cb-17d0-44b5-9776-005fced8e618",
		},
	},
	CategoryIAM + "/iam_custom_role_has_permissions_to_administer_resource_locks": {
		Score: scoreHigh,
		Tag:   []string{"AzureRole"},
		Recommend: recommend{
			Risk:           "In Azure, resource locks are a way to prevent accidental deletion or modification of critical resources. These locks can be set at the resource group level or the individual resource level. Resource locks administration is a critical task that should be preformed from a custom role with the appropriate permissions. This ensures that only authorized users can administer resource locks.",
			Recommendation: "Resouce locks are needed to prevent accidental deletion or modification of critical Azure resources. The administration of resource locks should be performed from a custom role with the appropriate permissions.\n- https://www.trendmicro.com/cloudoneconformity-staging/knowledge-base/azure/AccessControl/resource-lock-custom-role.html",
		},
	},
	CategoryIAM + "/iam_subscription_roles_owner_custom_not_created": {
		Score: scoreHigh,
		Tag:   []string{"AzureRole"},
		Recommend: recommend{
			Risk:           "Subscription ownership should not include permission to create custom owner roles. The principle of least privilege should be followed and only necessary privileges should be assigned instead of allowing full administrative access.",
			Recommendation: "Custom subscription owner roles should not be created. This is because the principle of least privilege should be followed and only necessary privileges should be assigned instead of allowing full administrative access\n- https://www.trendmicro.com/cloudoneconformity-staging/knowledge-base/azure/AccessControl/remove-custom-owner-roles.html",
		},
	},
	CategoryKeyVault + "/keyvault_key_expiration_set_in_non_rbac": {
		Score: scoreHigh,
		Tag:   []string{"KeyVault"},
		Recommend: recommend{
			Risk:           "Azure Key Vault enables users to store and use cryptographic keys within the Microsoft Azure environment. The exp (expiration date) attribute identifies the expiration date on or after which the key MUST NOT be used for a cryptographic operation. By default, keys never expire. It is thus recommended that keys be rotated in the key vault and set an explicit expiration date for all keys. This ensures that the keys cannot be used beyond their assigned lifetimes.",
			Recommendation: "From Azure Portal: 1. Go to Key vaults. 2. For each Key vault, click on Keys. 3. In the main pane, ensure that an appropriate Expiration date is set for any keys that are Enabled. From Azure CLI: Update the Expiration date for the key using the below command: az keyvault key set-attributes --name <keyName> --vault-name <vaultName> -- expires Y-m-d'T'H:M:S'Z' Note: To view the expiration date on all keys in a Key Vault using Microsoft API, the 'List' Key permission is required. To update the expiration date for the keys: 1. Go to the Key vault, click on Access Control (IAM). 2. Click on Add role assignment and assign the role of Key Vault Crypto Officer to the appropriate user. From PowerShell: Set-AzKeyVaultKeyAttribute -VaultName <VaultName> -Name <KeyName> -Expires <DateTime>\n- https://docs.microsoft.com/en-us/rest/api/keyvault/about-keys--secrets-and-certificates#key-vault-keys",
		},
	},
	CategoryKeyVault + "/keyvault_key_rotation_enabled": {
		Score: scoreHigh,
		Tag:   []string{"KeyVault"},
		Recommend: recommend{
			Risk:           "Once set up, Automatic Private Key Rotation removes the need for manual administration when keys expire at intervals determined by your organization's policy. The recommended key lifetime is 2 years. Your organization should determine its own key expiration policy.",
			Recommendation: "Note: Azure CLI and Powershell use ISO8601 flags to input timespans. Every timespan input will be in the format P<timespanInISO8601Format>(Y,M,D). The leading P is required with it denoting period. The (Y,M,D) are for the duration of Year, Month,and Day respectively. A time frame of 2 years, 2 months, 2 days would be (P2Y2M2D). From Azure Portal 1. From Azure Portal select the Portal Menu in the top left. 2. Select Key Vaults. 3. Select a Key Vault to audit. 4. Under Objects select Keys. 5. Select a key to audit. 6. In the top row select Rotation policy. 7. Select an Expiry time. 8. Set Enable auto rotation to Enabled. 9. Set an appropriate Rotation option and Rotation time. 10. Optionally set the Notification time. 11. Select Save. 12. Repeat steps 3-11 for each Key Vault and Key. From PowerShell Run the following command for each key to update its policy: Set-AzKeyVaultKeyRotationPolicy -VaultName test-kv -Name test-key -PolicyPath rotation_policy.json\n- https://docs.microsoft.com/en-us/azure/storage/common/customer-managed-keys-overview#update-the-key-version",
		},
	},
	CategoryKeyVault + "/keyvault_logging_enabled": {
		Score: scoreMedium,
		Tag:   []string{"KeyVault"},
		Recommend: recommend{
			Risk:           "Monitoring how and when key vaults are accessed, and by whom, enables an audit trail of interactions with confidential information, keys, and certificates managed by Azure Keyvault. Enabling logging for Key Vault saves information in an Azure storage account which the user provides. This creates a new container named insights-logs-auditevent automatically for the specified storage account. This same storage account can be used for collecting logs for multiple key vaults.",
			Recommendation: "1. Go to Key vaults 2. For each Key vault 3. Go to Diagnostic settings 4. Click on Edit Settings 5. Ensure that Archive to a storage account is Enabled 6. Ensure that AuditEvent is checked, and the retention days is set to 180 days or as appropriate\n- https://docs.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-data-protection#dp-8-ensure-security-of-key-and-certificate-repository",
		},
	},
	CategoryKeyVault + "/keyvault_non_rbac_secret_expiration_set": {
		Score: scoreHigh,
		Tag:   []string{"KeyVault"},
		Recommend: recommend{
			Risk:           "The Azure Key Vault enables users to store and keep secrets within the Microsoft Azure environment. Secrets in the Azure Key Vault are octet sequences with a maximum size of 25k bytes each. The exp (expiration date) attribute identifies the expiration date on or after which the secret MUST NOT be used. By default, secrets never expire. It is thus recommended to rotate secrets in the key vault and set an explicit expiration date for all secrets. This ensures that the secrets cannot be used beyond their assigned lifetimes.",
			Recommendation: "From Azure Portal: 1. Go to Key vaults. 2. For each Key vault, click on Secrets. 3. In the main pane, ensure that the status of the secret is Enabled. 4. Set an appropriate Expiration date on all secrets. From Azure CLI: Update the Expiration date for the secret using the below command: az keyvault secret set-attributes --name <secretName> --vault-name <vaultName> --expires Y-m-d'T'H:M:S'Z' Note: To view the expiration date on all secrets in a Key Vault using Microsoft API, the List Key permission is required. To update the expiration date for the secrets: 1. Go to Key vault, click on Access policies. 2. Click on Create and add an access policy with the Update permission (in the Secret Permissions - Secret Management Operations section). From PowerShell: For each Key vault with the EnableRbacAuthorization setting set to False or empty, run the following command. Set-AzKeyVaultSecret -VaultName <Vault Name> -Name <Secret Name> -Expires <DateTime>\n- https://docs.microsoft.com/en-us/rest/api/keyvault/about-keys--secrets-and-certificates#key-vault-secrets",
		},
	},
	CategoryKeyVault + "/keyvault_private_endpoints": {
		Score: scoreHigh,
		Tag:   []string{"KeyVault"},
		Recommend: recommend{
			Risk:           "Private endpoints will keep network requests to Azure Key Vault limited to the endpoints attached to the resources that are whitelisted to communicate with each other. Assigning the Key Vault to a network without an endpoint will allow other resources on that network to view all traffic from the Key Vault to its destination. In spite of the complexity in configuration, this is recommended for high security secrets.",
			Recommendation: "Please see the additional information about the requirements needed before starting this remediation procedure. From Azure Portal 1. From Azure Home open the Portal Menu in the top left. 2. Select Key Vaults. 3. Select a Key Vault to audit. 4. Select Networking in the left column. 5. Select Private endpoint connections from the top row. 6. Select + Create. 7. Select the subscription the Key Vault is within, and other desired configuration. 8. Select Next. 9. For resource type select Microsoft.KeyVault/vaults. 10. Select the Key Vault to associate the Private Endpoint with. 11. Select Next. 12. In the Virtual Networking field, select the network to assign the Endpoint. 13. Select other configuration options as desired, including an existing or new application security group. 14. Select Next. 15. Select the private DNS the Private Endpoints will use. 16. Select Next. 17. Optionally add Tags. 18. Select Next : Review + Create. 19. Review the information and select Create. Follow the Audit Procedure to determine if it has successfully applied. 20. Repeat steps 3-19 for each Key Vault. From Azure CLI 1. To create an endpoint, run the following command: az network private-endpoint create --resource-group <resourceGroup --vnet- name <vnetName> --subnet <subnetName> --name <PrivateEndpointName> -- private-connection-resource-id '/subscriptions/<AZURE SUBSCRIPTION ID>/resourceGroups/<resourceGroup>/providers/Microsoft.KeyVault/vaults/<keyVa ultName>' --group-ids vault --connection-name <privateLinkConnectionName> -- location <azureRegion> --manual-request 2. To manually approve the endpoint request, run the following command: az keyvault private-endpoint-connection approve --resource-group <resourceGroup> --vault-name <keyVaultName> –name <privateLinkName> 4. Determine the Private Endpoint's IP address to connect the Key Vault to the Private DNS you have previously created: 5. Look for the property networkInterfaces then id, the value must be placed in the variable <privateEndpointNIC> within step 7. az network private-endpoint show -g <resourceGroupName> -n <privateEndpointName> 6. Look for the property networkInterfaces then id, the value must be placed on <privateEndpointNIC> in step 7. az network nic show --ids <privateEndpointName> 7. Create a Private DNS record within the DNS Zone you created for the Private Endpoint: az network private-dns record-set a add-record -g <resourcecGroupName> -z 'privatelink.vaultcore.azure.net' -n <keyVaultName> -a <privateEndpointNIC> 8. nslookup the private endpoint to determine if the DNS record is correct: nslookup <keyVaultName>.vault.azure.net nslookup <keyVaultName>.privatelink.vaultcore.azure.n\n- https://docs.microsoft.com/en-us/azure/storage/common/storage-private-endpoints",
		},
	},
	CategoryKeyVault + "/keyvault_rbac_enabled": {
		Score: scoreHigh,
		Tag:   []string{"KeyVault"},
		Recommend: recommend{
			Risk:           "The new RBAC permissions model for Key Vaults enables a much finer grained access control for key vault secrets, keys, certificates, etc., than the vault access policy. This in turn will permit the use of privileged identity management over these roles, thus securing the key vaults with JIT Access management.",
			Recommendation: "From Azure Portal Key Vaults can be configured to use Azure role-based access control on creation. For existing Key Vaults: 1. From Azure Home open the Portal Menu in the top left corner 2. Select Key Vaults 3. Select a Key Vault to audit 4. Select Access configuration 5. Set the Permission model radio button to Azure role-based access control, taking note of the warning message 6. Click Save 7. Select Access Control (IAM) 8. Select the Role Assignments tab 9. Reapply permissions as needed to groups or users\n- https://docs.microsoft.com/en-gb/azure/role-based-access-control/role-assignments-portal?tabs=current",
		},
	},
	CategoryKeyVault + "/keyvault_rbac_key_expiration_set": {
		Score: scoreHigh,
		Tag:   []string{"KeyVault"},
		Recommend: recommend{
			Risk:           "Azure Key Vault enables users to store and use cryptographic keys within the Microsoft Azure environment. The exp (expiration date) attribute identifies the expiration date on or after which the key MUST NOT be used for encryption of new data, wrapping of new keys, and signing. By default, keys never expire. It is thus recommended that keys be rotated in the key vault and set an explicit expiration date for all keys to help enforce the key rotation. This ensures that the keys cannot be used beyond their assigned lifetimes.",
			Recommendation: "From Azure Portal: 1. Go to Key vaults. 2. For each Key vault, click on Keys. 3. In the main pane, ensure that an appropriate Expiration date is set for any keys that are Enabled. From Azure CLI: Update the Expiration date for the key using the below command: az keyvault key set-attributes --name <keyName> --vault-name <vaultName> -- expires Y-m-d'T'H:M:S'Z' Note: To view the expiration date on all keys in a Key Vault using Microsoft API, the 'List' Key permission is required. To update the expiration date for the keys: 1. Go to the Key vault, click on Access Control (IAM). 2. Click on Add role assignment and assign the role of Key Vault Crypto Officer to the appropriate user. From PowerShell: Set-AzKeyVaultKeyAttribute -VaultName <VaultName> -Name <KeyName> -Expires <DateTime>\n- https://docs.microsoft.com/en-us/rest/api/keyvault/about-keys--secrets-and-certificates#key-vault-keys",
		},
	},
	CategoryKeyVault + "/keyvault_rbac_secret_expiration_set": {
		Score: scoreHigh,
		Tag:   []string{"KeyVault"},
		Recommend: recommend{
			Risk:           "The Azure Key Vault enables users to store and keep secrets within the Microsoft Azure environment. Secrets in the Azure Key Vault are octet sequences with a maximum size of 25k bytes each. The exp (expiration date) attribute identifies the expiration date on or after which the secret MUST NOT be used. By default, secrets never expire. It is thus recommended to rotate secrets in the key vault and set an explicit expiration date for all secrets. This ensures that the secrets cannot be used beyond their assigned lifetimes.",
			Recommendation: "From Azure Portal: 1. Go to Key vaults. 2. For each Key vault, click on Secrets. 3. In the main pane, ensure that the status of the secret is Enabled. 4. For each enabled secret, ensure that an appropriate Expiration date is set. From Azure CLI: Update the Expiration date for the secret using the below command: az keyvault secret set-attributes --name <secretName> --vault-name <vaultName> --expires Y-m-d'T'H:M:S'Z' Note: To view the expiration date on all secrets in a Key Vault using Microsoft API, the List Key permission is required. To update the expiration date for the secrets: 1. Go to the Key vault, click on Access Control (IAM). 2. Click on Add role assignment and assign the role of Key Vault Secrets Officer to the appropriate user. From PowerShell: Set-AzKeyVaultSecretAttribute -VaultName <Vault Name> -Name <Secret Name> - Expires <DateTime>\n- https://docs.microsoft.com/en-us/rest/api/keyvault/about-keys--secrets-and-certificates#key-vault-secrets",
		},
	},
	CategoryKeyVault + "/keyvault_recoverable": {
		Score: scoreHigh,
		Tag:   []string{"KeyVault"},
		Recommend: recommend{
			Risk:           "There could be scenarios where users accidentally run delete/purge commands on Key Vault or an attacker/malicious user deliberately does so in order to cause disruption. Deleting or purging a Key Vault leads to immediate data loss, as keys encrypting data and secrets/certificates allowing access/services will become non-accessible. There are 2 Key Vault properties that play a role in permanent unavailability of a Key Vault: 1. enableSoftDelete: Setting this parameter to 'true' for a Key Vault ensures that even if Key Vault is deleted, Key Vault itself or its objects remain recoverable for the next 90 days. Key Vault/objects can either be recovered or purged (permanent deletion) during those 90 days. If no action is taken, key vault and its objects will subsequently be purged. 2. enablePurgeProtection: enableSoftDelete only ensures that Key Vault is not deleted permanently and will be recoverable for 90 days from date of deletion. However, there are scenarios in which the Key Vault and/or its objects are accidentally purged and hence will not be recoverable. Setting enablePurgeProtection to 'true' ensures that the Key Vault and its objects cannot be purged. Enabling both the parameters on Key Vaults ensures that Key Vaults and their objects cannot be deleted/purged permanently.",
			Recommendation: "To enable 'Do Not Purge' and 'Soft Delete' for a Key Vault: From Azure Portal 1. Go to Key Vaults 2. For each Key Vault 3. Click Properties 4. Ensure the status of soft-delete reads Soft delete has been enabled on this key vault. 5. At the bottom of the page, click 'Enable Purge Protection' Note, once enabled you cannot disable it. From Azure CLI az resource update --id /subscriptions/xxxxxx-xxxx-xxxx-xxxx- xxxxxxxxxxxx/resourceGroups/<resourceGroupName>/providers/Microsoft.KeyVault /vaults/<keyVaultName> --set properties.enablePurgeProtection=true properties.enableSoftDelete=true From PowerShell Update-AzKeyVault -VaultName <vaultName -ResourceGroupName <resourceGroupName -EnablePurgeProtection\n- https://blogs.technet.microsoft.com/kv/2017/05/10/azure-key-vault-recovery-options/",
		},
	},
	CategoryMonitor + "/monitor_alert_create_policy_assignment": {
		Score: scoreHigh,
		Tag:   []string{"Monitor"},
		Recommend: recommend{
			Risk:           "Monitoring for create policy assignment events gives insight into changes done in 'Azure policy - assignments' and can reduce the time it takes to detect unsolicited changes.",
			Recommendation: "1. Navigate to the Monitor blade. 2. Select Alerts. 3. Select Create. 4. Select Alert rule. 5. Under Filter by subscription, choose a subscription. 6. Under Filter by resource type, select Policy assignment (policyAssignments). 7. Under Filter by location, select All. 8. From the results, select the subscription. 9. Select Done. 10. Select the Condition tab. 11. Under Signal name, click Create policy assignment (Microsoft.Authorization/policyAssignments). 12. Select the Actions tab. 13. To use an existing action group, click elect action groups. To create a new action group, click Create action group. Fill out the appropriate details for the selection. 14. Select the Details tab. 15. Select a Resource group, provide an Alert rule name and an optional Alert rule description. 16. Click Review + create. 17. Click Create.\n- https://docs.microsoft.com/en-in/azure/azure-monitor/platform/alerts-activity-log",
		},
	},
	CategoryMonitor + "/monitor_alert_create_update_nsg": {
		Score: scoreHigh,
		Tag:   []string{"Monitor"},
		Recommend: recommend{
			Risk:           "Monitoring for Create or Update Network Security Group events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.",
			Recommendation: "1. Navigate to the Monitor blade. 2. Select Alerts. 3. Select Create. 4. Select Alert rule. 5. Under Filter by subscription, choose a subscription. 6. Under Filter by resource type, select Network security groups. 7. Under Filter by location, select All. 8. From the results, select the subscription. 9. Select Done. 10. Select the Condition tab. 11. Under Signal name, click Create or Update Network Security Group (Microsoft.Network/networkSecurityGroups). 12. Select the Actions tab. 13. To use an existing action group, click Select action groups. To create a new action group, click Create action group. Fill out the appropriate details for the selection. 14. Select the Details tab. 15. Select a Resource group, provide an Alert rule name and an optional Alert rule description. 16. Click Review + create. 17. Click Create.\n- https://azure.microsoft.com/en-us/updates/classic-alerting-monitoring-retirement",
		},
	},
	CategoryMonitor + "/monitor_alert_create_update_public_ip_address_rule": {
		Score: scoreHigh,
		Tag:   []string{"Monitor"},
		Recommend: recommend{
			Risk:           "Monitoring for Create or Update Public IP Address events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.",
			Recommendation: "1. Navigate to the Monitor blade. 2. Select Alerts. 3. Select Create. 4. Select Alert rule. 5. Under Filter by subscription, choose a subscription. 6. Under Filter by resource type, select Public IP addresses. 7. Under Filter by location, select All. 8. From the results, select the subscription. 9. Select Done. 10. Select the Condition tab. 11. Under Signal name, click Create or Update Public Ip Address (Microsoft.Network/publicIPAddresses). 12. Select the Actions tab. 13. To use an existing action group, click Select action groups. To create a new action group, click Create action group. Fill out the appropriate details for the selection. 14. Select the Details tab. 15. Select a Resource group, provide an Alert rule name and an optional Alert rule description. 16. Click Review + create. 17. Click Create.\n- https://azure.microsoft.com/en-us/updates/classic-alerting-monitoring-retirement",
		},
	},
	CategoryMonitor + "/monitor_alert_create_update_security_solution": {
		Score: scoreHigh,
		Tag:   []string{"Monitor"},
		Recommend: recommend{
			Risk:           "Monitoring for Create or Update Security Solution events gives insight into changes to the active security solutions and may reduce the time it takes to detect suspicious activity.",
			Recommendation: "1. Navigate to the Monitor blade. 2. Select Alerts. 3. Select Create. 4. Select Alert rule. 5. Under Filter by subscription, choose a subscription. 6. Under Filter by resource type, select Security Solutions (securitySolutions). 7. Under Filter by location, select All. 8. From the results, select the subscription. 9. Select Done. 10. Select the Condition tab. 11. Under Signal name, click Create or Update Security Solutions (Microsoft.Security/securitySolutions). 12. Select the Actions tab. 13. To use an existing action group, click Select action groups. To create a new action group, click Create action group. Fill out the appropriate details for the selection. 14. Select the Details tab. 15. Select a Resource group, provide an Alert rule name and an optional Alert rule description. 16. Click Review + create. 17. Click Create.\n- https://azure.microsoft.com/en-us/updates/classic-alerting-monitoring-retirement",
		},
	},
	CategoryMonitor + "/monitor_alert_create_update_sqlserver_fr": {
		Score: scoreHigh,
		Tag:   []string{"Monitor"},
		Recommend: recommend{
			Risk:           "Monitoring for Create or Update SQL Server Firewall Rule events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.",
			Recommendation: "1. Navigate to the Monitor blade. 2. Select Alerts. 3. Select Create. 4. Select Alert rule. 5. Under Filter by subscription, choose a subscription. 6. Under Filter by resource type, select Server Firewall Rule (servers/firewallRules). 7. Under Filter by location, select All. 8. From the results, select the subscription. 9. Select Done. 10. Select the Condition tab. 11. Under Signal name, click Create/Update server firewall rule (Microsoft.Sql/servers/firewallRules). 12. Select the Actions tab. 13. To use an existing action group, click Select action groups. To create a new action group, click Create action group. Fill out the appropriate details for the selection. 14. Select the Details tab. 15. Select a Resource group, provide an Alert rule name and an optional Alert rule description. 16. Click Review + create. 17. Click Create.\n- https://azure.microsoft.com/en-us/updates/classic-alerting-monitoring-retirement",
		},
	},
	CategoryMonitor + "/monitor_alert_delete_nsg": {
		Score: scoreHigh,
		Tag:   []string{"Monitor"},
		Recommend: recommend{
			Risk:           "Monitoring for 'Delete Network Security Group' events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.",
			Recommendation: "1. Navigate to the Monitor blade. 2. Select Alerts. 3. Select Create. 4. Select Alert rule. 5. Under Filter by subscription, choose a subscription. 6. Under Filter by resource type, select Network security groups. 7. Under Filter by location, select All. 8. From the results, select the subscription. 9. Select Done. 10. Select the Condition tab. 11. Under Signal name, click Delete Network Security Group (Microsoft.Network/networkSecurityGroups). 12. Select the Actions tab. 13. To use an existing action group, click Select action groups. To create a new action group, click Create action group. Fill out the appropriate details for the selection. 14. Select the Details tab. 15. Select a Resource group, provide an Alert rule name and an optional Alert rule description. 16. Click Review + create. 17. Click Create.\n- https://azure.microsoft.com/en-us/updates/classic-alerting-monitoring-retirement",
		},
	},
	CategoryMonitor + "/monitor_alert_delete_policy_assignment": {
		Score: scoreHigh,
		Tag:   []string{"Monitor"},
		Recommend: recommend{
			Risk:           "Monitoring for delete policy assignment events gives insight into changes done in 'azure policy - assignments' and can reduce the time it takes to detect unsolicited changes.",
			Recommendation: "1. Navigate to the Monitor blade. 2. Select Alerts. 3. Select Create. 4. Select Alert rule. 5. Under Filter by subscription, choose a subscription. 6. Under Filter by resource type, select Policy assignment (policyAssignments). 7. Under Filter by location, select All. 8. From the results, select the subscription. 9. Select Done. 10. Select the Condition tab. 11. Under Signal name, click Delete policy assignment (Microsoft.Authorization/policyAssignments). 12. Select the Actions tab. 13. To use an existing action group, click Select action groups. To create a new action group, click Create action group. Fill out the appropriate details for the selection. 14. Select the Details tab. 15. Select a Resource group, provide an Alert rule name and an optional Alert rule description. 16. Click Review + create. 17. Click Create.\n- https://docs.microsoft.com/en-in/azure/azure-monitor/platform/alerts-activity-log",
		},
	},
	CategoryMonitor + "/monitor_alert_delete_public_ip_address_rule": {
		Score: scoreHigh,
		Tag:   []string{"Monitor"},
		Recommend: recommend{
			Risk:           "Monitoring for Delete Public IP Address events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.",
			Recommendation: "1. Navigate to the Monitor blade. 2. Select Alerts. 3. Select Create. 4. Select Alert rule. 5. Under Filter by subscription, choose a subscription. 6. Under Filter by resource type, select Public IP addresses. 7. Under Filter by location, select All. 8. From the results, select the subscription. 9. Select Done. 10. Select the Condition tab. 11. Under Signal name, click Delete Public Ip Address (Microsoft.Network/publicIPAddresses). 12. Select the Actions tab. 13. To use an existing action group, click Select action groups. To create a new action group, click Create action group. Fill out the appropriate details for the selection. 14. Select the Details tab. 15. Select a Resource group, provide an Alert rule name and an optional Alert rule description. 16. Click Review + create. 17. Click Create.\n- https://azure.microsoft.com/en-us/updates/classic-alerting-monitoring-retirement",
		},
	},
	CategoryMonitor + "/monitor_alert_delete_security_solution": {
		Score: scoreHigh,
		Tag:   []string{"Monitor"},
		Recommend: recommend{
			Risk:           "Monitoring for Delete Security Solution events gives insight into changes to the active security solutions and may reduce the time it takes to detect suspicious activity.",
			Recommendation: "1. Navigate to the Monitor blade. 2. Select Alerts. 3. Select Create. 4. Select Alert rule. 5. Under Filter by subscription, choose a subscription. 6. Under Filter by resource type, select Security Solutions (securitySolutions). 7. Under Filter by location, select All. 8. From the results, select the subscription. 9. Select Done. 10. Select the Condition tab. 11. Under Signal name, click Delete Security Solutions (Microsoft.Security/securitySolutions). 12. Select the Actions tab. 13. To use an existing action group, click Select action groups. To create a new action group, click Create action group. Fill out the appropriate details for the selection. 14. Select the Details tab. 15. Select a Resource group, provide an Alert rule name and an optional Alert rule description. 16. Click Review + create. 17. Click Create.curitySolutions). 7. Under Filter by location, select All. 8. From the results, select the subscription. 9. Select Done. 10. Select the Condition tab. 11. Under Signal name, click Create or Update Security Solutions (Microsoft.Security/securitySolutions). 12. Select the Actions tab. 13. To use an existing action group, click Select action groups. To create a new action group, click Create action group. Fill out the appropriate details for the selection. 14. Select the Details tab. 15. Select a Resource group, provide an Alert rule name and an optional Alert rule description. 16. Click Review + create. 17. Click Create.\n- https://azure.microsoft.com/en-us/updates/classic-alerting-monitoring-retirement",
		},
	},
	CategoryMonitor + "/monitor_alert_delete_sqlserver_fr": {
		Score: scoreHigh,
		Tag:   []string{"Monitor"},
		Recommend: recommend{
			Risk:           "Monitoring for Delete SQL Server Firewall Rule events gives insight into SQL network access changes and may reduce the time it takes to detect suspicious activity.",
			Recommendation: "1. Navigate to the Monitor blade. 2. Select Alerts. 3. Select Create. 4. Select Alert rule. 5. Under Filter by subscription, choose a subscription. 6. Under Filter by resource type, select Server Firewall Rule (servers/firewallRules). 7. Under Filter by location, select All. 8. From the results, select the subscription. 9. Select Done. 10. Select the Condition tab. 11. Under Signal name, click Delete server firewall rule (Microsoft.Sql/servers/firewallRules). 12. Select the Actions tab. 13. To use an existing action group, click Select action groups. To create a new action group, click Create action group. Fill out the appropriate details for the selection. 14. Select the Details tab. 15. Select a Resource group, provide an Alert rule name and an optional Alert rule description. 16. Click Review + create. 17. Click Create.\n- https://azure.microsoft.com/en-us/updates/classic-alerting-monitoring-retirement",
		},
	},
	CategoryMonitor + "/monitor_diagnostic_setting_with_appropriate_categories": {
		Score: scoreMedium,
		Tag:   []string{"Configuring Diagnostic Settings", "Monitor"},
		Recommend: recommend{
			Risk:           "A diagnostic setting controls how the diagnostic log is exported. Capturing the diagnostic setting categories for appropriate control/management plane activities allows proper alerting.",
			Recommendation: "1. Go to Azure Monitor 2. Click Activity log 3. Click on Export Activity Logs 4. Select the Subscription from the drop down menu 5. Click on Add diagnostic setting 6. Enter a name for your new Diagnostic Setting 7. Check the following categories: Administrative, Alert, Policy, and Security 8. Choose the destination details according to your organization's needs.\n- https://learn.microsoft.com/en-us/azure/storage/common/manage-storage-analytics-logs?toc=%2Fazure%2Fstorage%2Fblobs%2Ftoc.json&bc=%2Fazure%2Fstorage%2Fblobs%2Fbreadcrumb%2Ftoc.json&tabs=azure-portal",
		},
	},
	CategoryMonitor + "/monitor_diagnostic_settings_exists": {
		Score: scoreMedium,
		Tag:   []string{"Monitor"},
		Recommend: recommend{
			Risk:           "A diagnostic setting controls how a diagnostic log is exported. By default, logs are retained only for 90 days. Diagnostic settings should be defined so that logs can be exported and stored for a longer duration in order to analyze security activities within an Azure subscription.",
			Recommendation: "To enable Diagnostic Settings on a Subscription: 1. Go to Monitor 2. Click on Activity Log 3. Click on Export Activity Logs 4. Click + Add diagnostic setting 5. Enter a Diagnostic setting name 6. Select Categories for the diagnostic settings 7. Select the appropriate Destination details (this may be Log Analytics, Storage Account, Event Hub, or Partner solution) 8. Click Save To enable Diagnostic Settings on a specific resource: 1. Go to Monitor 2. Click Diagnostic settings 3. Click on the resource that has a diagnostics status of disabled 4. Select Add Diagnostic Setting 5. Enter a Diagnostic setting name 6. Select the appropriate log, metric, and destination. (this may be Log Analytics, Storage Account, Event Hub, or Partner solution) 7. Click save Repeat these step for all resources as needed.\n- https://docs.microsoft.com/en-us/azure/monitoring-and-diagnostics/monitoring-overview-activity-logs#export-the-activity-log-with-a-log-profile",
		},
	},
	CategoryMonitor + "/monitor_storage_account_with_activity_logs_cmk_encrypted": {
		Score: scoreMedium,
		Tag:   []string{"Monitor"},
		Recommend: recommend{
			Risk:           "Configuring the storage account with the activity log export container to use CMKs provides additional confidentiality controls on log data, as a given user must have read permission on the corresponding storage account and must be granted decrypt permission by the CMK.",
			Recommendation: "1. Go to Activity log 2. Select Export 3. Select Subscription 4. In section Storage Account, note the name of the Storage account 5. Close the Export Audit Logs blade. Close the Monitor - Activity Log blade. 6. In right column, Click service Storage Accounts to access Storage account blade 7. Click on the storage account name noted in step 4. This will open blade specific to that storage account 8. Under Security + networking, click Encryption. 9. Ensure Customer-managed keys is selected and Key URI is set.\n- https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log?tabs=cli#managing-legacy-log-profiles",
		},
	},
	CategoryMonitor + "/monitor_storage_container_with_activity_logs_is_private": {
		Score: scoreHigh,
		Tag:   []string{"Monitor"},
		Recommend: recommend{
			Risk:           "Allowing public access to activity log content may aid an adversary in identifying weaknesses in the affected account's use or configuration.",
			Recommendation: "1. From Azure Home select the Portal Menu 2. Search for Storage Accounts to access Storage account blade 3. Click on the storage account name 4. Click on Configuration under settings 5. Select Enabled under 'Allow Blob public access'\n- https://docs.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-network-security#ns-2-secure-cloud-services-with-network-controls",
		},
	},
	CategoryMySQL + "/mysql_flexible_server_audit_log_connection_activated": {
		Score: scoreMedium,
		Tag:   []string{"Microsoft.DBforMySQL/flexibleServers"},
		Recommend: recommend{
			Risk:           "Enabling CONNECTION helps MySQL Database to log items such as successful and failed connection attempts to the server. Log data can be used to identify, troubleshoot, and repair configuration errors and suboptimal performance.",
			Recommendation: "1. From Azure Home select the Portal Menu. 2. Select Azure Database for MySQL servers. 3. Select a database. 4. Under Settings, select Server parameters. 5. Update audit_log_enabled parameter to ON. 6. Update audit_log_events parameter to have at least CONNECTION checked. 7. Click Save. 8. Under Monitoring, select Diagnostic settings. 9. Select + Add diagnostic setting. 10. Provide a diagnostic setting name. 11. Under Categories, select MySQL Audit Logs. 12. Specify destination details. 13. Click Save.\n- https://docs.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-logging-threat-detection#lt-3-enable-logging-for-security-investigation",
		},
	},
	CategoryMySQL + "/mysql_flexible_server_audit_log_enabled": {
		Score: scoreMedium,
		Tag:   []string{"Microsoft.DBforMySQL/flexibleServers"},
		Recommend: recommend{
			Risk:           "Enabling audit_log_enabled helps MySQL Database to log items such as connection attempts to the server, DDL/DML access, and more. Log data can be used to identify, troubleshoot, and repair configuration errors and suboptimal performance.",
			Recommendation: "1. Login to Azure Portal using https://portal.azure.com. 2. Select Azure Database for MySQL Servers. 3. Select a database. 4. Under Settings, select Server parameters. 5. Update audit_log_enabled parameter to ON 6. Under Monitoring, select Diagnostic settings. 7. Select + Add diagnostic setting. 8. Provide a diagnostic setting name. 9. Under Categories, select MySQL Audit Logs. 10. Specify destination details. 11. Click Save.\n- https://docs.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-logging-threat-detection#lt-3-enable-logging-for-security-investigation",
		},
	},
	CategoryMySQL + "/mysql_flexible_server_minimum_tls_version_12": {
		Score: scoreHigh,
		Tag:   []string{"Microsoft.DBforMySQL/flexibleServers"},
		Recommend: recommend{
			Risk:           "TLS connectivity helps to provide a new layer of security by connecting database server to client applications using Transport Layer Security (TLS). Enforcing TLS connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.",
			Recommendation: "1. Login to Azure Portal using https://portal.azure.com 2. Go to Azure Database for MySQL flexible servers 3. For each database, click on Server parameters under Settings 4. In the search box, type in tls_version 5. Click on the VALUE dropdown, and ensure only TLSV1.2 is selected for tls_version\n- https://docs.microsoft.com/en-us/azure/mysql/howto-configure-ssl",
		},
	},
	CategoryMySQL + "/mysql_flexible_server_ssl_connection_enabled": {
		Score: scoreHigh,
		Tag:   []string{"Microsoft.DBforMySQL/flexibleServers"},
		Recommend: recommend{
			Risk:           "SSL connectivity helps to provide a new layer of security by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.",
			Recommendation: "1. Login to Azure Portal using https://portal.azure.com 2. Go to Azure Database for MySQL servers 3. For each database, click on Connection security 4. In SSL settings, click on ENABLED to Enforce SSL connections\n- https://docs.microsoft.com/en-us/azure/mysql/single-server/how-to-configure-ssl",
		},
	},
	CategoryNetwork + "/network_bastion_host_exists": {
		Score: scoreMedium,
		Tag:   []string{"Network"},
		Recommend: recommend{
			Risk:           "The Azure Bastion service allows organizations a more secure means of accessing Azure Virtual Machines over the Internet without assigning public IP addresses to those Virtual Machines. The Azure Bastion service provides Remote Desktop Protocol (RDP) and Secure Shell (SSH) access to Virtual Machines using TLS within a web browser, thus preventing organizations from opening up 3389/TCP and 22/TCP to the Internet on Azure Virtual Machines. Additional benefits of the Bastion service includes Multi-Factor Authentication, Conditional Access Policies, and any other hardening measures configured within Azure Active Directory using a central point of access.",
			Recommendation: "From Azure Portal* 1. Click on Bastions 2. Select the Subscription 3. Select the Resource group 4. Type a Name for the new Bastion host 5. Select a Region 6. Choose Standard next to Tier 7. Use the slider to set the Instance count 8. Select the Virtual network or Create new 9. Select the Subnet named AzureBastionSubnet. Create a Subnet named AzureBastionSubnet using a /26 CIDR range if it doesn't already exist. 10. Selct the appropriate Public IP address option. 11. If Create new is selected for the Public IP address option, provide a Public IP address name. 12. If Use existing is selected for Public IP address option, select an IP address from Choose public IP address 13. Click Next: Tags > 14. Configure the appropriate Tags 15. Click Next: Advanced > 16. Select the appropriate Advanced options 17. Click Next: Review + create > 18. Click Create From Azure CLI az network bastion create --location <location> --name <name of bastion host> --public-ip-address <public IP address name or ID> --resource-group <resource group name or ID> --vnet-name <virtual network containing subnet called 'AzureBastionSubnet'> --scale-units <integer> --sku Standard [--disable-copy- paste true|false] [--enable-ip-connect true|false] [--enable-tunneling true|false] From PowerShell Create the appropriate Virtual network settings and Public IP Address settings. $subnetName = 'AzureBastionSubnet' $subnet = New-AzVirtualNetworkSubnetConfig -Name $subnetName -AddressPrefix <IP address range in CIDR notation making sure to use a /26> $virtualNet = New-AzVirtualNetwork -Name <virtual network name> - ResourceGroupName <resource group name> -Location <location> -AddressPrefix <IP address range in CIDR notation> -Subnet $subnet $publicip = New-AzPublicIpAddress -ResourceGroupName <resource group name> - Name <public IP address name> -Location <location> -AllocationMethod Dynamic -Sku Standard\n- https://learn.microsoft.com/en-us/powershell/module/az.network/get-azbastion?view=azps-9.2.0",
		},
	},
	CategoryNetwork + "/network_flow_log_captured_sent": {
		Score: scoreHigh,
		Tag:   []string{"Network"},
		Recommend: recommend{
			Risk:           "Network Flow Logs provide valuable insight into the flow of traffic around your network and feed into both Azure Monitor and Azure Sentinel (if in use), permitting the generation of visual flow diagrams to aid with analyzing for lateral movement, etc.",
			Recommendation: "1. Navigate to Network Watcher. 2. Select NSG flow logs. 3. Select + Create. 4. Select the desired Subscription. 5. Select + Select NSG. 6. Select a network security group. 7. Click Confirm selection. 8. Select or create a new Storage Account. 9. Input the retention in days to retain the log. 10. Click Next. 11. Under Configuration, select Version 2. 12. If rich analytics are required, select Enable Traffic Analytics, a processing interval, and a Log Analytics Workspace. 13. Select Next. 14. Optionally add Tags. 15. Select Review + create. 16. Select Create. Warning The remediation policy creates remediation deployment and names them by concatenating the subscription name and the resource group name. The MAXIMUM permitted length of a deployment name is 64 characters. Exceeding this will cause the remediation task to fail.\n- https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-nsg-flow-logging-portal",
		},
	},
	CategoryNetwork + "/network_flow_log_more_than_90_days": {
		Score: scoreMedium,
		Tag:   []string{"Network"},
		Recommend: recommend{
			Risk:           "Flow logs enable capturing information about IP traffic flowing in and out of network security groups. Logs can be used to check for anomalies and give insight into suspected breaches.",
			Recommendation: "From Azure Portal 1. Go to Network Watcher 2. Select NSG flow logs blade in the Logs section 3. Select each Network Security Group from the list 4. Ensure Status is set to On 5. Ensure Retention (days) setting greater than 90 days 6. Select your storage account in the Storage account field 7. Select Save From Azure CLI Enable the NSG flow logs and set the Retention (days) to greater than or equal to 90 days. az network watcher flow-log configure --nsg <NameorID of the Network Security Group> --enabled true --resource-group <resourceGroupName> --retention 91 --storage-account <NameorID of the storage account to save flow logs>\n- https://docs.microsoft.com/en-us/cli/azure/network/watcher/flow-log?view=azure-cli-latest",
		},
	},
	CategoryNetwork + "/network_http_internet_access_restricted": {
		Score: scoreHigh,
		Tag:   []string{"Network"},
		Recommend: recommend{
			Risk:           "The potential security problem with using HTTP(S) over the Internet is that attackers can use various brute force techniques to gain access to Azure resources. Once the attackers gain access, they can use the resource as a launch point for compromising other resources within the Azure tenant.",
			Recommendation: "Where HTTP(S) is not explicitly required and narrowly configured for resources attached to the Network Security Group, Internet-level access to your Azure resources should be restricted or eliminated. For internal access to relevant resources, configure an encrypted network tunnel such as: ExpressRoute Site-to-site VPN Point-to-site VPN\n- ",
		},
	},
	CategoryNetwork + "/network_public_ip_shodan": {
		Score: scoreHigh,
		Tag:   []string{"Network"},
		Recommend: recommend{
			Risk:           "If an Azure Public IP is exposed in Shodan, it can be accessed by anyone on the internet. This can lead to unauthorized access to your resources.",
			Recommendation: "Check Identified IPs, Consider changing them to private ones and delete them from Shodan.\n- https://www.shodan.io/",
		},
	},
	CategoryNetwork + "/network_rdp_internet_access_restricted": {
		Score: scoreHigh,
		Tag:   []string{"Network"},
		Recommend: recommend{
			Risk:           "The potential security problem with using RDP over the Internet is that attackers can use various brute force techniques to gain access to Azure Virtual Machines. Once the attackers gain access, they can use a virtual machine as a launch point for compromising other machines on an Azure Virtual Network or even attack networked devices outside of Azure.",
			Recommendation: "Where RDP is not explicitly required and narrowly configured for resources attached to the Network Security Group, Internet-level access to your Azure resources should be restricted or eliminated. For internal access to relevant resources, configure an encrypted network tunnel such as: ExpressRoute Site-to-site VPN Point-to-site VPN\n- https://docs.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-network-security#ns-1-establish-network-segmentation-boundaries",
		},
	},
	CategoryNetwork + "/network_ssh_internet_access_restricted": {
		Score: scoreHigh,
		Tag:   []string{"Network"},
		Recommend: recommend{
			Risk:           "The potential security problem with using SSH over the Internet is that attackers can use various brute force techniques to gain access to Azure Virtual Machines. Once the attackers gain access, they can use a virtual machine as a launch point for compromising other machines on the Azure Virtual Network or even attack networked devices outside of Azure.",
			Recommendation: "Where SSH is not explicitly required and narrowly configured for resources attached to the Network Security Group, Internet-level access to your Azure resources should be restricted or eliminated. For internal access to relevant resources, configure an encrypted network tunnel such as: ExpressRoute Site-to-site VPN Point-to-site VPN\n- https://docs.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-network-security#ns-1-establish-network-segmentation-boundaries",
		},
	},
	CategoryNetwork + "/network_udp_internet_access_restricted": {
		Score: scoreHigh,
		Tag:   []string{"Network"},
		Recommend: recommend{
			Risk:           "The potential security problem with broadly exposing UDP services over the Internet is that attackers can use DDoS amplification techniques to reflect spoofed UDP traffic from Azure Virtual Machines. The most common types of these attacks use exposed DNS, NTP, SSDP, SNMP, CLDAP and other UDP-based services as amplification sources for disrupting services of other machines on the Azure Virtual Network or even attack networked devices outside of Azure.",
			Recommendation: "Where UDP is not explicitly required and narrowly configured for resources attached tothe Network Security Group, Internet-level access to your Azure resources should be restricted or eliminated. For internal access to relevant resources, configure an encrypted network tunnel such as: ExpressRouteSite-to-site VPN Point-to-site VPN\n- https://docs.microsoft.com/en-us/azure/security/fundamentals/ddos-best-practices",
		},
	},
	CategoryNetwork + "/network_watcher_enabled": {
		Score: scoreMedium,
		Tag:   []string{"Network"},
		Recommend: recommend{
			Risk:           "Network diagnostic and visualization tools available with Network Watcher help users understand, diagnose, and gain insights to the network in Azure.",
			Recommendation: "Opting out of Network Watcher automatic enablement is a permanent change. Once you opt-out you cannot opt-in without contacting support.\n- https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v2-logging-threat-detection#lt-3-enable-logging-for-azure-network-activities",
		},
	},
	CategoryPolicy + "/policy_ensure_asc_enforcement_enabled": {
		Score: scoreMedium,
		Tag:   []string{"Microsoft.Authorization/policyAssignments"},
		Recommend: recommend{
			Risk:           "A security policy defines the desired configuration of your workloads and helps ensure compliance with company or regulatory security requirements. ASC Default policy is associated with every subscription by default. ASC default policy assignment is a set of security recommendations based on best practices. Enabling recommendations in ASC default policy ensures that Azure security center provides the ability to monitor all of the supported recommendations and optionally allow automated action for a few of the supported recommendations.",
			Recommendation: "1. From Azure Home select the Portal Menu 2. Select Policy 3. Select ASC Default for each subscription 4. Click on 'view Assignment' 5. Click on 'Edit assignment' 6. Ensure Policy Enforcement is Enabled 7. Click 'Review + Save'\n- https://learn.microsoft.com/en-us/azure/defender-for-cloud/implement-security-recommendations",
		},
	},
	CategoryPostgreSQL + "/postgresql_flexible_server_allow_access_services_disabled": {
		Score: scoreMedium,
		Tag:   []string{"PostgreSQL"},
		Recommend: recommend{
			Risk:           "If access from Azure services is enabled, the server's firewall will accept connections from all Azure resources, including resources not in your subscription. This is usually not a desired configuration. Instead, set up firewall rules to allow access from specific network ranges or VNET rules to allow access from specific virtual networks.",
			Recommendation: "From Azure Portal 1. Login to Azure Portal using https://portal.azure.com. 2. Go to Azure Database for PostgreSQL servers. 3. For each database, click on Connection security. 4. Under Firewall rules, set Allow access to Azure services to No. 5. Click Save. From Azure CLI Use the below command to delete the AllowAllWindowsAzureIps rule for PostgreSQL Database. az postgres server firewall-rule delete --name AllowAllWindowsAzureIps -- resource-group <resourceGroupName> --server-name <serverName>\n- https://learn.microsoft.com/en-us/azure/postgresql/single-server/quickstart-create-server-database-azure-cli#configure-a-server-based-firewall-rule",
		},
	},
	CategoryPostgreSQL + "/postgresql_flexible_server_connection_throttling_on": {
		Score: scoreMedium,
		Tag:   []string{"PostgreSQL"},
		Recommend: recommend{
			Risk:           "Enabling connection_throttling helps the PostgreSQL Database to Set the verbosity of logged messages. This in turn generates query and error logs with respect to concurrent connections that could lead to a successful Denial of Service (DoS) attack by exhausting connection resources. A system can also fail or be degraded by an overload of legitimate users. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance.",
			Recommendation: "From Azure Portal 1. Login to Azure Portal using https://portal.azure.com. 2. Go to Azure Database for PostgreSQL servers. 3. For each database, click on Server parameters. 4. Search for connection_throttling. 5. Click ON and save. From Azure CLI Use the below command to update connection_throttling configuration. az postgres server configuration set --resource-group <resourceGroupName> -- server-name <serverName> --name connection_throttling --value on From PowerShell Use the below command to update connection_throttling configuration. Update-AzPostgreSqlConfiguration -ResourceGroupName <ResourceGroupName> - ServerName <ServerName> -Name connection_throttling -Value on\n- https://learn.microsoft.com/en-us/azure/postgresql/single-server/how-to-configure-server-parameters-using-portal",
		},
	},
	CategoryPostgreSQL + "/postgresql_flexible_server_enforce_ssl_enabled": {
		Score: scoreMedium,
		Tag:   []string{"PostgreSQL"},
		Recommend: recommend{
			Risk:           "SSL connectivity helps to provide a new layer of security by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.",
			Recommendation: "From Azure Portal 1. Login to Azure Portal using https://portal.azure.com 2. Go to Azure Database for PostgreSQL server 3. For each database, click on Connection security 4. In SSL settings, click on ENABLED to enforce SSL connections 5. Click Save From Azure CLI Use the below command to enforce ssl connection for PostgreSQL Database. az postgres server update --resource-group <resourceGroupName> --name <serverName> --ssl-enforcement Enabled From PowerShell Update-AzPostgreSqlServer -ResourceGroupName <ResourceGroupName > -ServerName <ServerName> -SslEnforcement Enabled\n- https://learn.microsoft.com/en-us/azure/postgresql/single-server/concepts-ssl-connection-security",
		},
	},
	CategoryPostgreSQL + "/postgresql_flexible_server_log_checkpoints_on": {
		Score: scoreMedium,
		Tag:   []string{"PostgreSQL"},
		Recommend: recommend{
			Risk:           "Enabling log_checkpoints helps the PostgreSQL Database to Log each checkpoint in turn generates query and error logs. However, access to transaction logs is not supported. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance.",
			Recommendation: "From Azure Portal 1. From Azure Home select the Portal Menu. 2. Go to Azure Database for PostgreSQL servers. 3. For each database, click on Server parameters. 4. Search for log_checkpoints. 5. Click ON and save. From Azure CLI Use the below command to update log_checkpoints configuration. az postgres server configuration set --resource-group <resourceGroupName> -- server-name <serverName> --name log_checkpoints --value on From PowerShell Update-AzPostgreSqlConfiguration -ResourceGroupName <ResourceGroupName> - ServerName <ServerName> -Name log_checkpoints -Value on\n- https://docs.microsoft.com/en-us/azure/postgresql/howto-configure-server-parameters-using-portal",
		},
	},
	CategoryPostgreSQL + "/postgresql_flexible_server_log_connections_on": {
		Score: scoreMedium,
		Tag:   []string{"PostgreSQL"},
		Recommend: recommend{
			Risk:           "Enabling log_connections helps PostgreSQL Database to log attempted connection to the server, as well as successful completion of client authentication. Log data can be used to identify, troubleshoot, and repair configuration errors and suboptimal performance.",
			Recommendation: "From Azure Portal 1. Login to Azure Portal using https://portal.azure.com. 2. Go to Azure Database for PostgreSQL servers. 3. For each database, click on Server parameters. 4. Search for log_connections. 5. Click ON and save. From Azure CLI Use the below command to update log_connections configuration. az postgres server configuration set --resource-group <resourceGroupName> -- server-name <serverName> --name log_connections --value on From PowerShell Use the below command to update log_connections configuration. Update-AzPostgreSqlConfiguration -ResourceGroupName <ResourceGroupName> - ServerName <ServerName> -Name log_connections -Value on\n- https://learn.microsoft.com/en-us/azure/postgresql/single-server/how-to-configure-server-parameters-using-portal",
		},
	},
	CategoryPostgreSQL + "/postgresql_flexible_server_log_disconnections_on": {
		Score: scoreMedium,
		Tag:   []string{"PostgreSQL"},
		Recommend: recommend{
			Risk:           "Enabling log_disconnections helps PostgreSQL Database to Logs end of a session, including duration, which in turn generates query and error logs. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance.",
			Recommendation: "From Azure Portal 1. From Azure Home select the Portal Menu 2. Go to Azure Database for PostgreSQL servers 3. For each database, click on Server parameters 4. Search for log_disconnections. 5. Click ON and save. From Azure CLI Use the below command to update log_disconnections configuration. az postgres server configuration set --resource-group <resourceGroupName> -- server-name <serverName> --name log_disconnections --value on From PowerShell Use the below command to update log_disconnections configuration. Update-AzPostgreSqlConfiguration -ResourceGroupName <ResourceGr\n- https://learn.microsoft.com/en-us/azure/postgresql/single-server/how-to-configure-server-parameters-using-portal",
		},
	},
	CategoryPostgreSQL + "/postgresql_flexible_server_log_retention_days_greater_3": {
		Score: scoreMedium,
		Tag:   []string{"PostgreSQL"},
		Recommend: recommend{
			Risk:           "Configuring log_retention_days determines the duration in days that Azure Database for PostgreSQL retains log files. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance.",
			Recommendation: "From Azure Portal 1. From Azure Home select the Portal Menu. 2. Go to Azure Database for PostgreSQL servers. 3. For each database, click on Server parameters. 4. Search for log_retention_days. 5. Input a value between 4 and 7 (inclusive) and click Save. From Azure CLI Use the below command to update log_retention_days configuration. az postgres server configuration set --resource-group <resourceGroupName> -- server-name <serverName> --name log_retention_days --value <4-7> From Powershell Use the below command to update log_retention_days configuration. Update-AzPostgreSqlConfiguration -ResourceGroupName <ResourceGroupName> - ServerName <ServerName> -Name log_retention_days -Value <4-7>\n- https://learn.microsoft.com/en-us/rest/api/postgresql/singleserver/configurations/list-by-server?view=rest-postgresql-singleserver-2017-12-01&tabs=HTTP",
		},
	},
	CategorySQLServer + "/sqlserver_auditing_enabled": {
		Score: scoreMedium,
		Tag:   []string{"SQLServer"},
		Recommend: recommend{
			Risk:           "Audit policies are used to store logs associated to the SQL server (for instance, successful/unsuccesful log in attempts). These logs may be useful to detect anomalies or to perform an investigation in case a security incident is detected",
			Recommendation: "Create an audit policy for the SQL server\n- ",
		},
	},
	CategorySQLServer + "/sqlserver_auditing_retention_90_days": {
		Score: scoreMedium,
		Tag:   []string{"SQLServer"},
		Recommend: recommend{
			Risk:           "Audit Logs can be used to check for anomalies and give insight into suspected breaches or misuse of information and access.",
			Recommendation: "1. Go to SQL servers 2. For each server instance 3. Click on Auditing 4. If storage is selected, expand Advanced properties 5. Set the Retention (days) setting greater than 90 days or 0 for unlimited retention. 6. Select Save\n- https://learn.microsoft.com/en-us/purview/audit-log-retention-policies",
		},
	},
	CategorySQLServer + "/sqlserver_azuread_administrator_enabled": {
		Score: scoreMedium,
		Tag:   []string{"SQLServer"},
		Recommend: recommend{
			Risk:           "Azure Active Directory provides a centralized way of managing identities. Using local SQL administrator identites makes it more difficult to manage user accounts. In addition, from Azure Active Directory, security policies can be enforced to users in centralized way.",
			Recommendation: "Enable an Azure Active Directory administrator\n- ",
		},
	},
	CategorySQLServer + "/sqlserver_microsoft_defender_enabled": {
		Score: scoreMedium,
		Tag:   []string{"SQLServer"},
		Recommend: recommend{
			Risk:           "Microsoft Defender for SQL is a unified package for advanced SQL security capabilities. Microsoft Defender is available for Azure SQL Database, Azure SQL Managed  classifying sensitive data, surfacing and mitigating potential database vulnerabilities, and detecting anomalous activities that could indicate a threat to your database. It provides a single go-to location for enabling and managing these capabilities.",
			Recommendation: "1. Go to SQL servers For each production SQL server instance: 2. Click Microsoft Defender for Cloud 3. Click Enable Microsoft Defender for SQL\n- https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-sql-usage",
		},
	},
	CategorySQLServer + "/sqlserver_tde_encrypted_with_cmk": {
		Score: scoreMedium,
		Tag:   []string{"SQLServer"},
		Recommend: recommend{
			Risk:           "Customer-managed key support for Transparent Data Encryption (TDE) allows user control of TDE encryption keys and restricts who can access them and when. Azure Key Vault, Azure cloud-based external key management system, is the first key management service where TDE has integrated support for Customer-managed keys. With Customer-managed key support, the database encryption key is protected by an asymmetric key stored in the Key Vault. The asymmetric key is set at the server level and inherited by all databases under that server",
			Recommendation: "1. Go to SQL servers For the desired server instance 2. Click On Transparent data encryption 3. Set Transparent data encryption to Customer-managed key 4. Browse through your key vaults to Select an existing key or create a new key in the Azure Key Vault. 5. Check Make selected key the default TDE protector\n- https://learn.microsoft.com/en-us/azure/azure-sql/database/transparent-data-encryption-byok-overview?view=azuresql",
		},
	},
	CategorySQLServer + "/sqlserver_tde_encryption_enabled": {
		Score: scoreMedium,
		Tag:   []string{"SQLServer"},
		Recommend: recommend{
			Risk:           "Azure SQL Database transparent data encryption helps protect against the threat of malicious activity by performing real-time encryption and decryption of the database, associated backups, and transaction log files at rest without requiring changes to the application.",
			Recommendation: "1. Go to SQL databases 2. For each DB instance 3. Click on Transparent data encryption 4. Set Data encryption to On\n- https://learn.microsoft.com/en-us/azure/azure-sql/database/transparent-data-encryption-byok-overview?view=azuresql",
		},
	},
	CategorySQLServer + "/sqlserver_unrestricted_inbound_access": {
		Score: scoreCritical,
		Tag:   []string{"SQLServer"},
		Recommend: recommend{
			Risk:           "Azure SQL servers provide a firewall that, by default, blocks all Internet connections. When the rule (0.0.0.0-255.255.255.255) is used, the server can be accessed by any source from the Internet, incrementing significantly the attack surface of the SQL Server. It is recommended to use more granular firewall rules.",
			Recommendation: "Remove firewall rules allowing all sources and, instead, use more granular rules\n- ",
		},
	},
	CategorySQLServer + "/sqlserver_va_emails_notifications_admins_enabled": {
		Score: scoreMedium,
		Tag:   []string{"SQLServer"},
		Recommend: recommend{
			Risk:           "VA scan reports and alerts will be sent to admins and subscription owners by enabling setting 'Also send email notifications to admins and subscription owners'. This may help in reducing time required for identifying risks and taking corrective measures.",
			Recommendation: "1. Go to SQL servers 2. Select a server instance 3. Click on Security Center 4. Select Configure next to Enabled at subscription-level 5. In Section Vulnerability Assessment Settings, configure Storage Accounts if not already 6. Check/enable 'Also send email notifications to admins and subscription owners' 7. Click Save\n- https://learn.microsoft.com/en-us/azure/defender-for-cloud/sql-azure-vulnerability-assessment-enable",
		},
	},
	CategorySQLServer + "/sqlserver_va_periodic_recurring_scans_enabled": {
		Score: scoreMedium,
		Tag:   []string{"SQLServer"},
		Recommend: recommend{
			Risk:           "VA setting 'Periodic recurring scans' schedules periodic (weekly) vulnerability scanning for the SQL server and corresponding Databases. Periodic and regular vulnerability scanning provides risk visibility based on updated known vulnerability signatures and best practices.",
			Recommendation: "1. Go to SQL servers 2. For each server instance 3. Click on Security Center 4. In Section Vulnerability Assessment Settings, set Storage Account if not already 5. Toggle 'Periodic recurring scans' to ON. 6. Click Save\n- https://learn.microsoft.com/en-us/azure/defender-for-cloud/sql-azure-vulnerability-assessment-enable",
		},
	},
	CategorySQLServer + "/sqlserver_va_scan_reports_configured": {
		Score: scoreMedium,
		Tag:   []string{"SQLServer"},
		Recommend: recommend{
			Risk:           "Vulnerability Assessment (VA) scan reports and alerts will be sent to email addresses configured at 'Send scan reports to'. This may help in reducing time required for identifying risks and taking corrective measures",
			Recommendation: "1. Go to SQL servers 2. Select a server instance 3. Select Microsoft Defender for Cloud 4. Select Configure next to Enablement status 5. Set Microsoft Defender for SQL to On 6. Under Vulnerability Assessment Settings, select a Storage Account 7. Set Periodic recurring scans to On 8. Under Send scan reports to, provide email addresses for data owners and stakeholders 9. Click Save\n- https://learn.microsoft.com/en-us/azure/defender-for-cloud/sql-azure-vulnerability-assessment-enable",
		},
	},
	CategorySQLServer + "/sqlserver_vulnerability_assessment_enabled": {
		Score: scoreMedium,
		Tag:   []string{"SQLServer"},
		Recommend: recommend{
			Risk:           "The Vulnerability Assessment service scans databases for known security vulnerabilities and highlights deviations from best practices, such as misconfigurations, excessive permissions, and unprotected sensitive data. Results of the scan include actionable steps to resolve each issue and provide customized remediation scripts where applicable. Additionally, an assessment report can be customized by setting an acceptable baseline for permission configurations, feature configurations, and database settings.",
			Recommendation: "1. Go to SQL servers 2. Select a server instance 3. Click on Security Center 4. Select Configure next to Enabled at subscription-level 5. In Section Vulnerability Assessment Settings, Click Select Storage account 6. Choose Storage Account (Existing or Create New). Click Ok 7. Click Save\n- https://learn.microsoft.com/en-us/azure/defender-for-cloud/sql-azure-vulnerability-assessment-enable",
		},
	},
	CategoryStorage + "/storage_blob_public_access_level_is_disabled": {
		Score: scoreMedium,
		Tag:   []string{"AzureStorageAccount"},
		Recommend: recommend{
			Risk:           "A user that accesses blob containers anonymously can use constructors that do not require credentials such as shared access signatures.",
			Recommendation: "Set 'Public access level' configuration setting to 'Private (no anonymous access)'\n- ",
		},
	},
	CategoryStorage + "/storage_default_network_access_rule_is_denied": {
		Score: scoreMedium,
		Tag:   []string{"AzureStorageAccount"},
		Recommend: recommend{
			Risk:           "Storage accounts should be configured to deny access to traffic from all networks (including internet traffic). Access can be granted to traffic from specific Azure Virtualnetworks, allowing a secure network boundary for specific applications to be built.Access can also be granted to public internet IP address ranges to enable connectionsfrom specific internet or on-premises clients. When network rules are configured, onlyapplications from allowed networks can access a storage account. When calling from anallowed network, applications continue to require proper authorization (a valid accesskey or SAS token) to access the storage account.",
			Recommendation: "1. Go to Storage Accounts 2. For each storage account, Click on the Networking blade 3. Click the Firewalls and virtual networks heading. 4. Ensure that you have elected to allow access from Selected networks 5. Add rules to allow traffic from specific network. 6. Click Save to apply your changes.\n- ",
		},
	},
	CategoryStorage + "/storage_ensure_azure_services_are_trusted_to_access_is_enabled": {
		Score: scoreMedium,
		Tag:   []string{"AzureStorageAccount"},
		Recommend: recommend{
			Risk:           "Not allowing to access storage account by Azure services the following services: Azure Backup, Azure Event Grid, Azure Site Recovery, Azure DevTest Labs, Azure Event Hubs, Azure Networking, Azure Monitor and Azure SQL Data Warehouse (when registered in the subscription), are not granted access to your storage account",
			Recommendation: "To allow these Azure services to work as intended and be able to access your storage account resources, you have to add an exception so that the trusted Microsoft Azure services can bypass your network rules\n- ",
		},
	},
	CategoryStorage + "/storage_ensure_encryption_with_customer_managed_keys": {
		Score: scoreHigh,
		Tag:   []string{"AzureStorageAccount"},
		Recommend: recommend{
			Risk:           "If you want to control and manage storage account contents encryption key yourself you must specify a customer-managed key",
			Recommendation: "Enable sensitive data encryption at rest using Customer Managed Keys rather than Microsoft Managed keys.\n- ",
		},
	},
	CategoryStorage + "/storage_ensure_minimum_tls_version_12": {
		Score: scoreMedium,
		Tag:   []string{"AzureStorageAccount"},
		Recommend: recommend{
			Risk:           "TLS versions 1.0 and 1.1 are known to be susceptible to certain Common Vulnerabilities and Exposures (CVE) weaknesses and attacks such as POODLE and BEAST",
			Recommendation: "Ensure that all your Microsoft Azure Storage accounts are using the latest available version of the TLS protocol.\n- ",
		},
	},
	CategoryStorage + "/storage_ensure_private_endpoints_in_storage_accounts": {
		Score: scoreMedium,
		Tag:   []string{"AzureStorageAccount"},
		Recommend: recommend{
			Risk:           "Storage accounts that are not configured to use Private Endpoints are accessible over the public internet. This can lead to data exfiltration and other security issues.",
			Recommendation: "Use Private Endpoints to access Storage Accounts\n- https://docs.microsoft.com/en-us/azure/storage/common/storage-private-endpoints",
		},
	},
	CategoryStorage + "/storage_ensure_soft_delete_is_enabled": {
		Score: scoreMedium,
		Tag:   []string{"AzureStorageAccount"},
		Recommend: recommend{
			Risk:           "Containers and Blob Storage data can be incorrectly deleted. An attacker/malicious user may do this deliberately in order to cause disruption. Deleting an Azure Storage blob causes immediate data loss. Enabling this configuration for Azure storage ensures that even if blobs/data were deleted from the storage account, Blobs/data objects are recoverable for a particular time which is set in the Retention policies ranging from 7 days to 365 days.",
			Recommendation: "From the Azure home page, open the hamburger menu in the top left or click on the arrow pointing right with 'More services' underneath. 2. Select Storage. 3. Select Storage Accounts. 4. For each Storage Account, navigate to Data protection in the left scroll column. 5. Check soft delete for both blobs and containers. Set the retention period to a sufficient length for your organization\n- https://docs.microsoft.com/en-us/azure/storage/blobs/storage-blob-soft-delete",
		},
	},
	CategoryStorage + "/storage_infrastructure_encryption_is_enabled": {
		Score: scoreLow,
		Tag:   []string{"AzureRole"},
		Recommend: recommend{
			Risk:           "Double encryption of Azure Storage data protects against a scenario where one of the encryption algorithms or keys may be compromised",
			Recommendation: "Enabling double encryption at the hardware level on top of the default software encryption for Storage Accounts accessing Azure storage solutions.\n- ",
		},
	},
	CategoryStorage + "/storage_key_rotation_90_days": {
		Score: scoreMedium,
		Tag:   []string{"AzureStorageAccount"},
		Recommend: recommend{
			Risk:           "If the access keys are not regenerated periodically, the likelihood of accidental exposures increases, which can lead to unauthorized access to your storage account resources.",
			Recommendation: "Ensure that Azure Storage account access keys are regenerated every 90 days in order to decrease the likelihood of accidental exposures and protect your storage account resources against unauthorized access.\n- https://learn.microsoft.com/en-us/azure/storage/common/storage-account-create?tabs=azure-portal#regenerate-storage-access-keys",
		},
	},
	CategoryStorage + "/storage_secure_transfer_required_is_enabled": {
		Score: scoreMedium,
		Tag:   []string{"AzureStorageAccount"},
		Recommend: recommend{
			Risk:           "Requests to the storage account sent outside of a secure connection can be eavesdropped",
			Recommendation: "Enable data encryption in transit.\n- ",
		},
	},
	CategoryVM + "/vm_ensure_attached_disks_encrypted_with_cmk": {
		Score: scoreHigh,
		Tag:   []string{"Microsoft.Compute/virtualMachines"},
		Recommend: recommend{
			Risk:           "Encrypting the IaaS VM's OS disk (boot volume) and Data disks (non-boot volume) ensures that the entire content is fully unrecoverable without a key, thus protecting the volume from unwanted reads. PMK (Platform Managed Keys) are enabled by default in Azure-managed disks and allow encryption at rest. CMK is recommended because it gives the customer the option to control which specific keys are used for the encryption and decryption of the disk. The customer can then change keys and increase security by disabling them instead of relying on the PMK key that remains unchanging. There is also the option to increase security further by using automatically rotating keys so that access to disk is ensured to be limited. Organizations should evaluate what their security requirements are, however, for the data stored on the disk. For high-risk data using CMK is a must, as it provides extra steps of security. If the data is low risk, PMK is enabled by default and provides sufficient data security.",
			Recommendation: "Note: Disks must be detached from VMs to have encryption changed. 1. Go to Virtual machines 2. For each virtual machine, go to Settings 3. Click on Disks 4. Click the ellipsis (...), then click Detach to detach the disk from the VM 5. Now search for Disks and locate the unattached disk 6. Click the disk then select Encryption 7. Change your encryption type, then select your encryption set 8. Click Save 9. Go back to the VM and re-attach the disk\n- https://learn.microsoft.com/en-us/azure/security/fundamentals/data-encryption-best-practices#protect-data-at-rest",
		},
	},
	CategoryVM + "/vm_ensure_unattached_disks_encrypted_with_cmk": {
		Score: scoreHigh,
		Tag:   []string{"Microsoft.Compute/virtualMachines"},
		Recommend: recommend{
			Risk:           "Managed disks are encrypted by default with Platform-managed keys. Using Customer-managed keys may provide an additional level of security or meet an organization's regulatory requirements. Encrypting managed disks ensures that its entire content is fully unrecoverable without a key and thus protects the volume from unwarranted reads. Even if the disk is not attached to any of the VMs, there is always a risk where a compromised user account with administrative access to VM service can mount/attach these data disks, which may lead to sensitive information disclosure and tampering.",
			Recommendation: "If data stored in the disk is no longer useful, refer to Azure documentation to delete unattached data disks at: https://learn.microsoft.com/en-us/rest/api/compute/disks/delete?view=rest-compute-2023-10-02&tabs=HTTP\n- https://learn.microsoft.com/en-us/azure/security/fundamentals/data-encryption-best-practices#protect-data-at-rest",
		},
	},
	CategoryVM + "/vm_ensure_using_managed_disks": {
		Score: scoreMedium,
		Tag:   []string{"Microsoft.Compute/virtualMachines"},
		Recommend: recommend{
			Risk:           "Managed disks are by default encrypted on the underlying hardware, so no additional encryption is required for basic protection. It is available if additional encryption is required. Managed disks are by design more resilient that storage accounts. For ARM-deployed Virtual Machines, Azure Adviser will at some point recommend moving VHDs to managed disks both from a security and cost management perspective.",
			Recommendation: "1. Using the search feature, go to Virtual Machines 2. Select the virtual machine you would like to convert 3. Select Disks in the menu for the VM 4. At the top select Migrate to managed disks 5. You may follow the prompts to convert the disk and finish by selecting Migrate to start the process\n- https://docs.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-data-protection#dp-4-enable-data-at-rest-encryption-by-default",
		},
	},
	CategoryVM + "/vm_trusted_launch_enabled": {
		Score: scoreHigh,
		Tag:   []string{"Microsoft.Compute/virtualMachines"},
		Recommend: recommend{
			Risk:           "Secure Boot and vTPM work together to protect your VM from a variety of boot attacks, including bootkits, rootkits, and firmware rootkits. Not enabling Trusted Launch in Azure VM can lead to increased vulnerability to rootkits and boot-level malware, reduced ability to detect and prevent unauthorized changes to the boot process, and a potential compromise of system integrity and data security.",
			Recommendation: "1. Go to Virtual Machines 2. For each VM, under Settings, click on Configuration on the left blade 3. Under Security Type, select 'Trusted Launch Virtual Machines' 4. Make sure Enable Secure Boot & Enable vTPM are checked 5. Click on Apply.\n- https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch-existing-vm?tabs=portal#enable-trusted-launch-on-existing-vm",
		},
	},
}
