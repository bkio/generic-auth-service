/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System;
using System.Collections.Generic;
using System.Threading;
using AuthService.Endpoints;
using AuthService.Endpoints.Common;
using AuthService.Endpoints.Controllers;
using BCloudServiceUtilities;
using BServiceUtilities;
using BWebServiceUtilities;
using ServiceUtilities;
using ServiceUtilities.All;
using Newtonsoft.Json.Linq;

namespace AuthService
{
    class Program
    {
        static void Main()
        {
            Console.WriteLine("Initializing the service...");

//#if (Debug || DEBUG)
//            if (!ServicesDebugOnlyUtilities.CalledFromMain()) return;
//#endif

            // In case of a cloud component dependency or environment variable is added/removed;
            // Relative terraform script and microservice-dependency-map.cs must be updated as well.

            /*
            * Common initialization step
            */
            if (!BServiceInitializer.Initialize(out BServiceInitializer ServInit,
                new string[][]
                {
                    new string[] { "AZ_SUBSCRIPTION_ID" },
                    new string[] { "AZ_TENANT_ID" },
                    new string[] { "AZ_CLIENT_ID" },
                    new string[] { "AZ_CLIENT_SECRET" },

                    new string[] { "AZ_RESOURCE_GROUP_NAME" },
                    new string[] { "AZ_RESOURCE_GROUP_LOCATION" },

                    new string[] { "AZ_STORAGE_SERVICE_URL" },
                    new string[] { "AZ_STORAGE_ACCOUNT_NAME" },
                    new string[] { "AZ_STORAGE_ACCOUNT_ACCESS_KEY" },

                    new string[] { "AZ_SERVICEBUS_NAMESPACE_ID" },
                    new string[] { "AZ_SERVICEBUS_NAMESPACE_CONNECTION_STRING" },
                    new string[] { "AZ_EVENTGRID_DOMAIN_ENDPOINT" },
                    new string[] { "AZ_EVENTGRID_DOMAIN_ACCESS_KEY" },

                    //new string[] { "MONGODB_CONNECTION_STRING" },
                    new string[] { "MONGODB_CLIENT_CONFIG" },
                    new string[] { "MONGODB_PASSWORD" },
                    new string[] { "MONGODB_DATABASE" },

                    new string[] { "DEPLOYMENT_BRANCH_NAME" },
                    new string[] { "DEPLOYMENT_BUILD_NUMBER" },

                    new string[] { "REDIS_ENDPOINT" },
                    new string[] { "REDIS_PORT" },
                    new string[] { "REDIS_PASSWORD" },
                    new string[] { "REDIS_SSL_ENABLED" },

                    new string[] { "SSO_SUPER_ADMINS" },
                    new string[] { "AZUREAD_APP_ID" },
                    new string[] { "AZUREAD_CLIENT_SECRET" },
                    new string[] { "AZUREAD_APP_OBJECT_ID" },

                    new string[] { "API_GATEWAY_PUBLIC_URL" },

                    new string[] { "INTERNAL_CALL_PRIVATE_KEY" }
                }))
                return;
            bool bInitSuccess = true;
            //bInitSuccess &= ServInit.WithTracingService();
            bInitSuccess &= ServInit.WithDatabaseService();
            bInitSuccess &= ServInit.WithPubSubService();
            bInitSuccess &= ServInit.WithMemoryService();
            if (!bInitSuccess) return;

            Resources_DeploymentManager.Get().SetDeploymentBranchNameAndBuildNumber(ServInit.RequiredEnvironmentVariables["DEPLOYMENT_BRANCH_NAME"], ServInit.RequiredEnvironmentVariables["DEPLOYMENT_BUILD_NUMBER"]);

            var RootPath = "/";
            if (ServInit.RequiredEnvironmentVariables["DEPLOYMENT_BRANCH_NAME"] != "master" && ServInit.RequiredEnvironmentVariables["DEPLOYMENT_BRANCH_NAME"] != "development")
            {
                RootPath = "/" + ServInit.RequiredEnvironmentVariables["DEPLOYMENT_BRANCH_NAME"] + "/";
            }

            Controller_SSOAccessToken.SetLocalServerPort(ServInit.ServerPort);
            Controller_SSOAccessToken.SetRootPath(RootPath);
            Controller_Rights_Internal.Get().SetLocalServerPort(ServInit.ServerPort);
            Controller_Rights_Internal.Get().SetRootPath(RootPath);

            CommonData.MemoryQueryParameters = new BMemoryQueryParameters()
            {
                Domain = Resources_DeploymentManager.Get().GetDeploymentBranchNameEscapedLoweredWithDash().ToUpper(),
                SubDomain = "COMMON_DATA",
                Identifier = "MEMORY_SERVICE_DATA"
            };
            var InternalCallPrivateKey = ServInit.RequiredEnvironmentVariables["INTERNAL_CALL_PRIVATE_KEY"];
            CommonData.INTERNAL_CALL_PRIVATE_KEY = InternalCallPrivateKey;

            Controller_DeliveryEnsurer.Get().SetDatabaseService(ServInit.DatabaseService);
            Controller_DeliveryEnsurer.Get().SetServiceIdentifier("auth-service", Actions.EAction.ACTION_AUTH_SERVICE_DELIVERY_ENSURER);
            Controller_AtomicDBOperation.Get().SetMemoryService(ServInit.MemoryService, CommonData.MemoryQueryParameters);

            Controller_Rights_Internal.Get().SetMemoryService(ServInit.MemoryService);

            Manager_PubSubService.Get().Setup(ServInit.PubSubService);

            var InitializerThread = new Thread(() =>
            {
                Thread.CurrentThread.IsBackground = true;

                ServInit.PubSubService.Subscribe(CommonData.MemoryQueryParameters, Manager_PubSubService.Get().OnMessageReceived_Internal,
                    (string Message) =>
                    {
                        ServInit.LoggingService.WriteLogs(BLoggingServiceMessageUtility.Single(EBLoggingServiceLogType.Error, Message), ServInit.ProgramID, "PubSubService");
                    });
                Controller_AtomicDBOperation.Get().StartTimeoutCheckOperation(WebServiceBaseTimeoutableProcessor.OnTimeoutNotificationReceived);

            });
            InitializerThread.Start();

            var AzureAD_TenantID = "common";
            if (ServInit.RequiredEnvironmentVariables.ContainsKey("AZ_TENANT_ID"))
            {
                AzureAD_TenantID = ServInit.RequiredEnvironmentVariables["AZ_TENANT_ID"];
            }

            var AzureAD_AppID = ServInit.RequiredEnvironmentVariables["AZUREAD_APP_ID"];
            var AzureAD_ClientSecret = ServInit.RequiredEnvironmentVariables["AZUREAD_CLIENT_SECRET"];
            var AzureAD_AppObjectID = ServInit.RequiredEnvironmentVariables["AZUREAD_APP_OBJECT_ID"];

            var SSOSuperAdmins = new List<string>();
            var SAsJsonString = ServInit.RequiredEnvironmentVariables["SSO_SUPER_ADMINS"];
            try
            {
                var SAsJArray = JArray.Parse(SAsJsonString);
                foreach (var SAsToken in SAsJArray)
                {
                    if (SAsToken.Type == JTokenType.String)
                    {
                        SSOSuperAdmins.Add(((string)SAsToken).ToLower());
                    }
                }
            }
            catch (Exception) { }

            var ApiGatewayPublicUrl = ServInit.RequiredEnvironmentVariables["API_GATEWAY_PUBLIC_URL"];
            new InternalCalls.SetCall(InternalCallPrivateKey, ServInit.MemoryService).Process_SetApiGatewayPublicUrl(ApiGatewayPublicUrl,
                    (string Message) =>
                    {
                        ServInit.LoggingService.WriteLogs(BLoggingServiceMessageUtility.Single(EBLoggingServiceLogType.Error, Message), ServInit.ProgramID, "WebService");
                    });

            /*
            * Web-http service initialization
            */
            var WebServiceEndpoints = new List<BWebPrefixStructure>()
            {
                new BWebPrefixStructure(new string[] { RootPath + "auth/internal/pubsub*" }, () => new InternalCalls.PubSub_To_AuthService(InternalCallPrivateKey, ServInit.DatabaseService, RootPath)),
                new BWebPrefixStructure(new string[] { RootPath + "auth/internal/cleanup*" }, () => new InternalCalls.CleanupCall(InternalCallPrivateKey, ServInit.DatabaseService, ServInit.MemoryService)),
                new BWebPrefixStructure(new string[] { RootPath + "auth/internal/fetch_user_ids_from_emails*" }, () => new InternalCalls.FetchUserIDsFromEmailsRequest(InternalCallPrivateKey, ServInit.DatabaseService)),
                new BWebPrefixStructure(new string[] { RootPath + "auth/internal/set*" }, () => new InternalCalls.SetCall(InternalCallPrivateKey, ServInit.MemoryService)),
                new BWebPrefixStructure(new string[] { RootPath + "auth/internal/create_test_user*" }, () => new InternalCalls.CreateTestUser(InternalCallPrivateKey, ServInit.DatabaseService, ServInit.ServerPort, RootPath)),
                new BWebPrefixStructure(new string[] { RootPath + "auth/internal/delete_test_user*" }, () => new InternalCalls.DeleteTestUser(InternalCallPrivateKey, ServInit.ServerPort, RootPath)),
                new BWebPrefixStructure(new string[] { RootPath + "auth/internal/synchronize_users_with_azure*" }, () => new InternalCalls.SynchronizeUsersWithAzureAD(InternalCallPrivateKey, AzureAD_TenantID, AzureAD_AppID, AzureAD_ClientSecret, AzureAD_AppObjectID, ServInit.DatabaseService, SSOSuperAdmins)),
                new BWebPrefixStructure(new string[] { RootPath + "auth/login/azure/token_refresh" }, () => new SSOAzureTokenRefreshRequest(ServInit.DatabaseService, ServInit.MemoryService, AzureAD_TenantID, AzureAD_AppID, AzureAD_ClientSecret, SSOSuperAdmins)/*For token refresh requests via Azure AD SSO Service*/),
                new BWebPrefixStructure(new string[] { RootPath + "auth/login/azure/*" }, () => new SSOAzureLoginCallback(ServInit.DatabaseService, ServInit.MemoryService, AzureAD_TenantID, AzureAD_AppID, AzureAD_ClientSecret, SSOSuperAdmins)/*For auto-redirect from Azure AD SSO Service*/),
                new BWebPrefixStructure(new string[] { RootPath + "auth/login/azure*" }, () => new SSOAzureLoginRequest(ServInit.DatabaseService, ServInit.MemoryService, AzureAD_TenantID, AzureAD_AppID, AzureAD_ClientSecret, SSOSuperAdmins)/*For login request via Azure AD SSO Service*/),
                new BWebPrefixStructure(new string[] { RootPath + "auth/login" }, () => new LoginRequest(ServInit.DatabaseService, ServInit.MemoryService)),
                new BWebPrefixStructure(new string[] { RootPath + "auth/access_check" }, () => new AccessCheckRequest(ServInit.DatabaseService, ServInit.MemoryService, AzureAD_TenantID, AzureAD_AppID, AzureAD_ClientSecret, SSOSuperAdmins)),
                new BWebPrefixStructure(new string[] { RootPath + "auth/list_registered_email_addresses" }, () => new ListRegisteredUserEmails(ServInit.DatabaseService)),
                new BWebPrefixStructure(new string[] { RootPath + "auth/users/*/access_methods/*" }, () => new User_DeleteUserAccessMethod_ForUser(ServInit.DatabaseService, ServInit.MemoryService, "users", "access_methods")),
                new BWebPrefixStructure(new string[] { RootPath + "auth/users/*/access_methods" }, () => new User_CreateListAccessMethods_ForUser(ServInit.DatabaseService, ServInit.MemoryService, "users")),
                new BWebPrefixStructure(new string[] { RootPath + "auth/users/*/base_access_rights/*" }, () => new User_UpdateDeleteBaseRight_ForUser(ServInit.DatabaseService, ServInit.MemoryService, "users", "base_access_rights")),
                new BWebPrefixStructure(new string[] { RootPath + "auth/users/*/base_access_rights" }, () => new User_AddListBaseRights_ForUser(ServInit.DatabaseService, ServInit.MemoryService, "users")),
                new BWebPrefixStructure(new string[] { RootPath + "auth/users/*" }, () => new User_GetUpdateDeleteUser(ServInit.DatabaseService, ServInit.MemoryService, "users")),
                new BWebPrefixStructure(new string[] { RootPath + "auth/users" }, () => new User_CreateListUsers(ServInit.DatabaseService))
            };
            var BWebService = new BWebService(WebServiceEndpoints.ToArray(), ServInit.ServerPort/*, ServInit.TracingService*/);
            BWebService.Run((string Message) =>
            {
                ServInit.LoggingService.WriteLogs(BLoggingServiceMessageUtility.Single(EBLoggingServiceLogType.Info, Message), ServInit.ProgramID, "WebService");
            });

            /*
            * Make main thread sleep forever
            */
            Thread.Sleep(Timeout.Infinite);
        }
    }
}