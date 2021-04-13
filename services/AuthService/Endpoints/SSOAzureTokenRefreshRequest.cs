/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System;
using System.Collections.Generic;
using System.Net;
using AuthService.Endpoints.Controllers;
using BCloudServiceUtilities;
using BCommonUtilities;
using BWebServiceUtilities;
using ServiceUtilities.All;
using Newtonsoft.Json.Linq;

namespace AuthService.Endpoints
{
    internal class SSOAzureTokenRefreshRequest : BppWebServiceBase
    {
        private readonly IBDatabaseServiceInterface DatabaseService;
        private readonly IBMemoryServiceInterface MemoryService;

        private readonly string AzureAD_TenantID;
        private readonly string AzureAD_AppID;
        private readonly string AzureAD_ClientSecret;

        private readonly List<string> SSOSuperAdmins;

        public SSOAzureTokenRefreshRequest(
            IBDatabaseServiceInterface _DatabaseService,
            IBMemoryServiceInterface _MemoryService, 
            string _AzureAD_TenantID,
            string _AzureAD_AppID,
            string _AzureAD_ClientSecret,
            List<string> _SSOSuperAdmins)
        {
            DatabaseService = _DatabaseService;
            MemoryService = _MemoryService;

            AzureAD_TenantID = _AzureAD_TenantID;
            AzureAD_AppID = _AzureAD_AppID;
            AzureAD_ClientSecret = _AzureAD_ClientSecret;

            SSOSuperAdmins = _SSOSuperAdmins;
        }

        protected override BWebServiceResponse OnRequestPP(HttpListenerContext Context, Action<string> _ErrorMessageAction = null)
        {
            GetTracingService()?.On_FromGatewayToService_Received(Context, _ErrorMessageAction);

            var Result = OnRequest_Internal(Context, _ErrorMessageAction);

            GetTracingService()?.On_FromServiceToGateway_Sent(Context, _ErrorMessageAction);

            return Result;
        }

        private BWebServiceResponse OnRequest_Internal(HttpListenerContext _Context, Action<string> _ErrorMessageAction = null)
        {
            if (_Context.Request.HttpMethod != "POST")
            {
                _ErrorMessageAction?.Invoke("SSOAzureTokenRefreshRequest: POST method is accepted. But received request method:  " + _Context.Request.HttpMethod);

                return BWebResponse.MethodNotAllowed("POST method is accepted. But received request method:  " + _Context.Request.HttpMethod);
            }

            if (!BWebUtilities.DoesContextContainHeader(out List<string> ClientAuthorizationHeaderValues, out string _, _Context, "client-authorization")
                || !BUtility.CheckAndGetFirstStringFromList(ClientAuthorizationHeaderValues, out string ClientAuthorization)
                || ClientAuthorization.Length == 0)
            {
                return BWebResponse.BadRequest("Authorization header must be set validly.");
            }

            //Check and try refresh if expired
            if (new Controller_SSOAccessToken(ClientAuthorization, DatabaseService, MemoryService, AzureAD_TenantID, AzureAD_AppID, AzureAD_ClientSecret, SSOSuperAdmins, _ErrorMessageAction)
                    .PerformCheckAndRefresh(
                        out Controller_SSOAccessToken.EPerformCheckAndRefreshSuccessStatus SuccessStatus, 
                        out ClientAuthorization, 
                        out string UserID, 
                        out string EmailAddressWithoutPostfix)
                && ClientAuthorization != null && ClientAuthorization.Length > 0)
            {
                return BWebResponse.StatusOK("Success.", new JObject()
                {
                    ["token"] = ClientAuthorization,
                    ["status"] = SuccessStatus == Controller_SSOAccessToken.EPerformCheckAndRefreshSuccessStatus.Refreshed ? "Refreshed" : "AlreadyValid",
                    ["userId"] = UserID,
                    ["email"] = EmailAddressWithoutPostfix
                });
            }

            return BWebResponse.Unauthorized("Please re-login.");
        }
    }
}