﻿/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

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

#if (Debug || DEBUG)
            if (!ServicesDebugOnlyUtilities.CalledFromMain()) return;
#endif

            // In case of a cloud component dependency or environment variable is added/removed;
            // Relative terraform script and microservice-dependency-map.cs must be updated as well.

            /*
            * Common initialization step
            */
            if (!BServiceInitializer.Initialize(out BServiceInitializer ServInit,
                new string[][]
                {
                    new string[] { "GOOGLE_CLOUD_PROJECT_ID" },
                    new string[] { "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_PLAIN_CREDENTIALS" },

                    new string[] { "DEPLOYMENT_BRANCH_NAME" },
                    new string[] { "DEPLOYMENT_BUILD_NUMBER" },

                    new string[] { "REDIS_ENDPOINT" },
                    new string[] { "REDIS_PORT" },
                    new string[] { "REDIS_PASSWORD" },

                    new string[] { "SSO_SUPER_ADMINS" },

                    new string[] { "AZURE_AD_APP_ID" },
                    new string[] { "AZURE_AD_CLIENT_SECRET" },

                    new string[] { "AZURE_AD_FETCH_USERS_CLIENT_ID" },
                    new string[] { "AZURE_AD_FETCH_USERS_CLIENT_SECRET" },
                    new string[] { "AZURE_AD_FETCH_USERS_APP_OBJECT_ID" },

                    new string[] { "AZURE_OAUTH2_TOKEN_REQUEST_URL" },

                    new string[] { "INTERNAL_CALL_PRIVATE_KEY" }
                }))
                return;
            bool bInitSuccess = true;
            bInitSuccess &= ServInit.WithTracingService();
            bInitSuccess &= ServInit.WithDatabaseService();
            bInitSuccess &= ServInit.WithPubSubService();
            bInitSuccess &= ServInit.WithMemoryService();
            if (!bInitSuccess) return;

            Resources_DeploymentManager.Get().SetDeploymentBranchNameAndBuildNumber(ServInit.RequiredEnvironmentVariables["DEPLOYMENT_BRANCH_NAME"], ServInit.RequiredEnvironmentVariables["DEPLOYMENT_BUILD_NUMBER"]);

            Controller_SSOAccessToken.SetLocalServerPort(ServInit.ServerPort);
            Controller_Rights_Internal.Get().SetLocalServerPort(ServInit.ServerPort);

            CommonData.MemoryQueryParameters = new BMemoryQueryParameters()
            {
                Domain = Resources_DeploymentManager.Get().GetDeploymentBranchNameEscapedLoweredWithDash().ToUpper(),
                SubDomain = "COMMON_DATA",
                Identifier = "MEMORY_SERVICE_DATA"
            };
            var InternalCallPrivateKey = ServInit.RequiredEnvironmentVariables["INTERNAL_CALL_PRIVATE_KEY"];
            CommonData.INTERNAL_CALL_PRIVATE_KEY = InternalCallPrivateKey;
            Console.WriteLine(InternalCallPrivateKey);

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

            var AzureAD_AppID = ServInit.RequiredEnvironmentVariables["AZURE_AD_APP_ID"];
            var AzureAD_ClientSecret = ServInit.RequiredEnvironmentVariables["AZURE_AD_CLIENT_SECRET"];

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

            var AzureFetchUsersClientID = ServInit.RequiredEnvironmentVariables["AZURE_AD_FETCH_USERS_CLIENT_ID"];
            var AzureFetchUsersClientSecret = ServInit.RequiredEnvironmentVariables["AZURE_AD_FETCH_USERS_CLIENT_SECRET"];
            var AzureFetchUsersAppObjectID = ServInit.RequiredEnvironmentVariables["AZURE_AD_FETCH_USERS_APP_OBJECT_ID"];

            var AzureOAuth2TokenRequestUrl = ServInit.RequiredEnvironmentVariables["AZURE_OAUTH2_TOKEN_REQUEST_URL"];

            /*
            * Web-http service initialization
            */
            var WebServiceEndpoints = new List<BWebPrefixStructure>()
            {
                new BWebPrefixStructure(new string[] { "/auth/internal/pubsub*" }, () => new InternalCalls.PubSub_To_AuthService(InternalCallPrivateKey, ServInit.DatabaseService)),
                new BWebPrefixStructure(new string[] { "/auth/internal/cleanup*" }, () => new InternalCalls.CleanupCall(InternalCallPrivateKey, ServInit.DatabaseService, ServInit.MemoryService)),
                new BWebPrefixStructure(new string[] { "/auth/internal/fetch_user_ids_from_emails*" }, () => new InternalCalls.FetchUserIDsFromEmailsRequest(InternalCallPrivateKey, ServInit.DatabaseService)),
                new BWebPrefixStructure(new string[] { "/auth/internal/set*" }, () => new InternalCalls.SetCall(InternalCallPrivateKey, ServInit.MemoryService)),
                new BWebPrefixStructure(new string[] { "/auth/internal/create_test_user*" }, () => new InternalCalls.CreateTestUser(InternalCallPrivateKey, ServInit.DatabaseService, ServInit.ServerPort)),
                new BWebPrefixStructure(new string[] { "/auth/internal/delete_test_user*" }, () => new InternalCalls.DeleteTestUser(InternalCallPrivateKey, ServInit.ServerPort)),
                new BWebPrefixStructure(new string[] { "/auth/internal/synchronize_users_with_azure*" }, () => new InternalCalls.SynchronizeUsersWithAzureAD(InternalCallPrivateKey, AzureOAuth2TokenRequestUrl, AzureFetchUsersClientID, AzureFetchUsersClientSecret, AzureFetchUsersAppObjectID, ServInit.DatabaseService, SSOSuperAdmins)),
                new BWebPrefixStructure(new string[] { "/auth/login/azure/token_refresh" }, () => new SSOAzureTokenRefreshRequest(ServInit.DatabaseService, ServInit.MemoryService, AzureAD_AppID, AzureAD_ClientSecret, SSOSuperAdmins)/*For token refresh requests via Azure AD SSO Service*/),
                new BWebPrefixStructure(new string[] { "/auth/login/azure/*" }, () => new SSOAzureLoginCallback(ServInit.DatabaseService, ServInit.MemoryService, AzureAD_AppID, AzureAD_ClientSecret, SSOSuperAdmins)/*For auto-redirect from Azure AD SSO Service*/),
                new BWebPrefixStructure(new string[] { "/auth/login/azure*" }, () => new SSOAzureLoginRequest(ServInit.DatabaseService, ServInit.MemoryService, AzureAD_AppID, AzureAD_ClientSecret, SSOSuperAdmins)/*For login request via Azure AD SSO Service*/),
                new BWebPrefixStructure(new string[] { "/auth/login" }, () => new LoginRequest(ServInit.DatabaseService, ServInit.MemoryService)),
                new BWebPrefixStructure(new string[] { "/auth/access_check" }, () => new AccessCheckRequest(ServInit.DatabaseService, ServInit.MemoryService, AzureAD_AppID, AzureAD_ClientSecret, SSOSuperAdmins)),
                new BWebPrefixStructure(new string[] { "/auth/list_registered_email_addresses" }, () => new ListRegisteredUserEmails(ServInit.DatabaseService)),
                new BWebPrefixStructure(new string[] { "/auth/users/*/access_methods/*" }, () => new User_DeleteUserAccessMethod_ForUser(ServInit.DatabaseService, ServInit.MemoryService, "users", "access_methods")),
                new BWebPrefixStructure(new string[] { "/auth/users/*/access_methods" }, () => new User_CreateListAccessMethods_ForUser(ServInit.DatabaseService, ServInit.MemoryService, "users")),
                new BWebPrefixStructure(new string[] { "/auth/users/*/base_access_rights/*" }, () => new User_UpdateDeleteBaseRight_ForUser(ServInit.DatabaseService, ServInit.MemoryService, "users", "base_access_rights")),
                new BWebPrefixStructure(new string[] { "/auth/users/*/base_access_rights" }, () => new User_AddListBaseRights_ForUser(ServInit.DatabaseService, ServInit.MemoryService, "users")),
                new BWebPrefixStructure(new string[] { "/auth/users/*" }, () => new User_GetUpdateDeleteUser(ServInit.DatabaseService, ServInit.MemoryService, "users")),
                new BWebPrefixStructure(new string[] { "/auth/users" }, () => new User_CreateListUsers(ServInit.DatabaseService))
            };
            var BWebService = new BWebService(WebServiceEndpoints.ToArray(), ServInit.ServerPort, ServInit.TracingService);
            BWebService.Run((string Message) =>
            {
                ServInit.LoggingService.WriteLogs(BLoggingServiceMessageUtility.Single(EBLoggingServiceLogType.Info, Message), ServInit.ProgramID, "WebService");
            });

            var ApiPassThroughEndpoint = Environment.GetEnvironmentVariable("API_PASSTHROUGH_ENDPOINT");
            if (ApiPassThroughEndpoint != null)
            {
                //Needed by MicroserviceLocalRunner
                new InternalCalls.SetCall(InternalCallPrivateKey, ServInit.MemoryService).Process_SetApiPassthroughPublicEndpoint(
                    (string Message) =>
                    {
                        ServInit.LoggingService.WriteLogs(BLoggingServiceMessageUtility.Single(EBLoggingServiceLogType.Error, Message), ServInit.ProgramID, "WebService");
                    }, ApiPassThroughEndpoint);
            }
            var CadFileServiceEndpoint = Environment.GetEnvironmentVariable("CAD_FILE_SERVICE_ENDPOINT");
            if (CadFileServiceEndpoint != null)
            {
                //Needed by MicroserviceLocalRunner
                new InternalCalls.SetCall(InternalCallPrivateKey, ServInit.MemoryService).Process_SetCADFileServicePublicEndpoint(
                    (string Message) =>
                    {
                        ServInit.LoggingService.WriteLogs(BLoggingServiceMessageUtility.Single(EBLoggingServiceLogType.Error, Message), ServInit.ProgramID, "WebService");
                    }, CadFileServiceEndpoint);
            }

            /*
            * Make main thread sleep forever
            */
            Thread.Sleep(Timeout.Infinite);
        }
    }
}