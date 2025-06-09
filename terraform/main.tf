terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "=4.22.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "=3.1.0"
    }
    azapi = {
      source = "azure/azapi"
      version = "=2.3.0"
    }
  }
}

provider "azurerm" {
  features {
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }

  subscription_id = var.subscription_id
}

resource "random_string" "unique" {
  length  = 8
  special = false
  upper   = false
}

data "azurerm_client_config" "current" {}

data "azurerm_log_analytics_workspace" "default" {
  name                = "DefaultWorkspace-${data.azurerm_client_config.current.subscription_id}-${local.loc_short}"
  resource_group_name = "DefaultResourceGroup-${local.loc_short}"
} 

resource "azurerm_resource_group" "rg" {
  name     = "rg-${local.gh_repo}-${random_string.unique.result}-${local.loc_for_naming}"
  location = var.location
  tags = local.tags
}

resource "azurerm_virtual_network" "default" {
  name                = "${local.func_name}-vnet-${local.loc_for_naming}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  address_space       = ["10.39.0.0/16"]

  tags = local.tags
}

resource "azurerm_subnet" "default" {
  name                 = "default-subnet-${local.loc_for_naming}"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.default.name
  address_prefixes     = ["10.39.0.0/24"]
}

# create NSG for the subnet
resource "azurerm_network_security_group" "nsg" {
  name                = "nsg-${local.func_name}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  security_rule {
    name                       = "AllowHTTP"
    priority                   = 1000
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["80","443"]
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowAppGW"
    priority                   = 1100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["65200-65535"]
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = local.tags
}

resource "azurerm_subnet_network_security_group_association" "nsg_association" {
  subnet_id                 = azurerm_subnet.default.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}


resource "azurerm_key_vault" "kv" {
  name                       = "kv-${local.func_name}"
  location                   = azurerm_resource_group.rg.location
  resource_group_name        = azurerm_resource_group.rg.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = false
  enable_rbac_authorization  = true

}

resource "azurerm_role_assignment" "kv_officer" {
  scope                            = azurerm_key_vault.kv.id
  role_definition_name             = "Key Vault Secrets Officer"
  principal_id                     = data.azurerm_client_config.current.object_id
}

resource "azurerm_role_assignment" "kv_cert_officer" {
  scope                            = azurerm_key_vault.kv.id
  role_definition_name             = "Key Vault Certificates Officer"
  principal_id                     = data.azurerm_client_config.current.object_id
}

resource "azurerm_key_vault_certificate" "cert" {
  depends_on = [ azurerm_role_assignment.kv_cert_officer ]
  name         = "root-cert"
  key_vault_id = azurerm_key_vault.kv.id
  certificate {
    contents = filebase64("root.pfx")
  }
  certificate_policy {
    issuer_parameters {
      name = "Self"
    }

    key_properties {
      exportable = true
      key_size   = 2048
      key_type   = "RSA"
      reuse_key  = false
    }

    secret_properties {
      content_type = "application/x-pkcs12"
    }
  }
}


resource "azurerm_application_insights" "app" {
  name                = "${local.func_name}-insights"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  application_type    = "other"
  workspace_id        = data.azurerm_log_analytics_workspace.default.id
}


resource "azurerm_storage_account" "sa" {
  name                     = "sa${local.func_name}"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location

  account_tier             = "Standard"
  account_replication_type = "LRS"

  allow_nested_items_to_be_public = false

  tags = local.tags
}

resource "azurerm_storage_container" "sc" {
  name                  = "app-package-${local.func_name}"
  storage_account_id    = azurerm_storage_account.sa.id
  container_access_type = "private"
}

resource "azurerm_service_plan" "asp" {
  name                = "asp${local.func_name}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  sku_name            = "FC1"
  os_type             = "Linux"

  tags = local.tags
}

resource "azurerm_function_app_flex_consumption" "this" {
  name                = "${local.func_name}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  service_plan_id     = azurerm_service_plan.asp.id

  storage_container_type      = "blobContainer"
  storage_container_endpoint  = "https://${azurerm_storage_account.sa.name}.blob.core.windows.net/${azurerm_storage_container.sc.name}"
  storage_authentication_type = "StorageAccountConnectionString"
  storage_access_key          = azurerm_storage_account.sa.primary_access_key
  runtime_name                = "python"
  runtime_version             = "3.12"
  maximum_instance_count      = 50
  instance_memory_in_mb       = 2048
  webdeploy_publish_basic_authentication_enabled = false

  client_certificate_enabled = true
  client_certificate_exclusion_paths = "/api/healthz"
  client_certificate_mode = "Required"

  site_config {
    application_insights_connection_string = azurerm_application_insights.app.connection_string
  }

  app_settings = {
    AZURE_SUBSCRIPTION_ID   = var.subscription_id
    AZURE_TENANT_ID         = data.azurerm_client_config.current.tenant_id
    ISSUER_CN               = var.issuer_cn
    SUBJECT_CN              = var.subject_cn
  }

  identity {
    type = "SystemAssigned"
  }

  tags = local.tags
}

resource "azurerm_role_assignment" "blob" {
  scope                = azurerm_storage_account.sa.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_function_app_flex_consumption.this.identity[0].principal_id
}

resource "azurerm_role_assignment" "cog" {
  scope                = azurerm_storage_account.sa.id
  role_definition_name = "Cognitive Services Contributor"
  principal_id         = azurerm_function_app_flex_consumption.this.identity[0].principal_id
}

resource "azurerm_role_assignment" "reader" {
  scope                = "/subscriptions/${var.subscription_id}"
  role_definition_name = "Reader"
  principal_id         = azurerm_function_app_flex_consumption.this.identity[0].principal_id
}

# resource "null_resource" "publish_func" {
#   depends_on = [
#     azurerm_role_assignment.blob
#   ]
#   triggers = {
#     index = "${timestamp()}"
#   }
#   provisioner "local-exec" {
#     command = "cd ../func && func azure functionapp publish ${azurerm_function_app_flex_consumption.this.name} --python"
#   }
# }

# create a public ip adress for the application gateway
resource "azurerm_public_ip" "app_gateway" {
  name                = "pip-appgw-${local.func_name}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = local.tags
}

# create an application gateway
# resource "azurerm_application_gateway" "app_gateway" {
#   name                = "appgw-${local.func_name}"
#   location            = azurerm_resource_group.rg.location
#   resource_group_name = azurerm_resource_group.rg.name
#   sku {
#     name     = "Standard_v2"
#     tier     = "Standard_v2"
#     capacity = 1
#   }

#   gateway_ip_configuration {
#     name      = "appgw-ip-config"
#     subnet_id = azurerm_subnet.default.id
#   }

#   frontend_port {
#     name = "appgw-frontend-port"
#     port = 80
#   }

#   frontend_port {
#     name = "appgw-frontend-port-https"
#     port = 443
#   }

#   frontend_ip_configuration {
#     name                 = "appgw-frontend-ip"
#     public_ip_address_id = azurerm_public_ip.app_gateway.id
#   }

#   backend_address_pool {
#     name  = "appgw-backend-pool"
#     fqdns = ["${azurerm_function_app_flex_consumption.this.name}.azurewebsites.net"]
#   }

#   backend_http_settings {
#     name                  = "appgw-backend-https-settings"
#     cookie_based_affinity = "Disabled"
#     port                  = 443
#     protocol              = "Https"
#     request_timeout       = 20
#     probe_name = "https-healthz"
#     host_name = "${azurerm_function_app_flex_consumption.this.name}.azurewebsites.net"

#   }

#   http_listener {
#     name                           = "appgw-http-listener"
#     frontend_ip_configuration_name = "appgw-frontend-ip"
#     frontend_port_name             = "appgw-frontend-port"
#     protocol                       = "Http"
#   }

#   http_listener {
#     name                          = "appgw-https-listener"
#     frontend_ip_configuration_name = "appgw-frontend-ip"
#     frontend_port_name             = "appgw-frontend-port-https"
#     protocol                       = "Https"
#     ssl_profile_name               = "pass-client-cert"
#     ssl_certificate_name           = "wildcard"
#   }

#   request_routing_rule {
#     name                       = "appgw-routing-rule"
#     priority                    = 10
#     rule_type                  = "Basic"
#     http_listener_name         = "appgw-http-listener"
#     backend_address_pool_name  = "appgw-backend-pool"
#     backend_http_settings_name = "appgw-backend-https-settings"
#   }

#   request_routing_rule {
#     name                       = "appgw-routing-rule-https"
#     priority                    = 20
#     rule_type                  = "Basic"
#     http_listener_name         = "appgw-https-listener"
#     backend_address_pool_name  = "appgw-backend-pool"
#     backend_http_settings_name = "appgw-backend-https-settings"
#     rewrite_rule_set_name      = "pass-client-cert"
#   }

#   probe {
#     name = "https-healthz"
#     protocol = "Https"
#     path = "/api/healthz"
#     interval = 30
#     timeout = 30
#     unhealthy_threshold = 3
#     pick_host_name_from_backend_http_settings = true

#     match {
#       status_code = ["200-399"]
#     }
#   }

#   probe {
#     name = "http-healthz"
#     protocol = "Http"
#     path = "/api/healthz"
#     interval = 30
#     timeout = 30
#     unhealthy_threshold = 3
#     pick_host_name_from_backend_http_settings = true

#     match {
#       status_code = ["200-399"]
#     }
#   }

#   rewrite_rule_set {
#     name = "pass-client-cert"
#     rewrite_rule {
#       name = "clientcert"  
#       rule_sequence = 100
#       request_header_configuration {
#         header_name = "X-ARR-Client-Cert"
#         header_value = "{var_client_certificate}"
#       }
#     }
#     rewrite_rule {
#       name          = "SimpleHeader"
#       rule_sequence = 110
#       request_header_configuration {
#         header_name  = "x-my-custom-header" 
#         header_value = "helloworld" 
#       }
#     }
#   } 

#   trusted_root_certificate {
#     name = "root-cert"
#     key_vault_secret_id = azurerm_key_vault_certificate.cert.secret_id
#   }

#   trusted_client_certificate {
#     name = "client-root-cert"
#     data = filebase64("root.crt")
#   }

#   ssl_certificate {
#     name = "wildcard"
#     key_vault_secret_id = "https://${azurerm_key_vault.kv.name}.vault.azure.net/secrets/wildcard"
#   }

#   ssl_profile {
#     name = "pass-client-cert"
#     trusted_client_certificate_names = [ "client-root-cert" ]
#     ssl_policy {
#       policy_name          = "AppGwSslPolicy20220101"
#       policy_type          = "Predefined"
#     }
#   }  

#   identity {
#     type = "UserAssigned"
#     identity_ids = [ azurerm_user_assigned_identity.appgw.id
#     ]
#   }
#   tags = local.tags

# }

resource "azurerm_user_assigned_identity" "appgw" {
  location            = azurerm_resource_group.rg.location
  name                = "uai-appgw-${local.func_name}"
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_role_assignment" "app_gateway_secrets" {
  scope                = azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.appgw.principal_id
}

resource "azurerm_role_assignment" "app_gateway_certs" {
  scope                = azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Certificate User"
  principal_id         = azurerm_user_assigned_identity.appgw.principal_id
}