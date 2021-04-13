/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System;
using System.Collections.Generic;
using System.Net;
using AuthService.Endpoints.Common;
using AuthService.Endpoints.Controllers;
using AuthService.Endpoints.Structures;
using BCloudServiceUtilities;
using BCommonUtilities;
using BWebServiceUtilities;
using ServiceUtilities.All;
using Newtonsoft.Json;

namespace AuthService.Endpoints
{
    internal class SSOAzureLoginRequest : BppWebServiceBase
    {
        private readonly IBDatabaseServiceInterface DatabaseService;
        private readonly IBMemoryServiceInterface MemoryService;

        private readonly string AzureAD_TenantID;
        private readonly string AzureAD_AppID;
        private readonly string AzureAD_ClientSecret;

        private readonly List<string> SSOSuperAdmins;

        private readonly string ApiGatewayPublicUrl;

        public const string DEFAULT_TENANT_NAME = "default";
        public const string DEFAULT_REDIRECT_URL_ENCODED = "http%3A%2F%2Flocalhost%3A56789";

        public SSOAzureLoginRequest(
            IBDatabaseServiceInterface _DatabaseService,
            IBMemoryServiceInterface _MemoryService, 
            string _AzureAD_TenantID,
            string _AzureAD_AppID,
            string _AzureAD_ClientSecret,
            List<string> _SSOSuperAdmins,
            string _ApiGatewayPublicUrl)
        {
            DatabaseService = _DatabaseService;
            MemoryService = _MemoryService;

            AzureAD_TenantID = _AzureAD_TenantID;
            AzureAD_AppID = _AzureAD_AppID;
            AzureAD_ClientSecret = _AzureAD_ClientSecret;

            SSOSuperAdmins = _SSOSuperAdmins;

            ApiGatewayPublicUrl = _ApiGatewayPublicUrl;
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
            if (!UrlParameters.TryGetValue("redirect_url", out string RedirectUrlEncoded) || RedirectUrlEncoded.Length == 0)
            {
                RedirectUrlEncoded = DEFAULT_REDIRECT_URL_ENCODED;
            }

            if (_Context.Request.HttpMethod != "GET")
            {
                _ErrorMessageAction?.Invoke("SSOLoginRequest: GET method is accepted. But received request method:  " + _Context.Request.HttpMethod);

                return SSOCommon.MakeCallerRedirected(WebUtility.UrlDecode(RedirectUrlEncoded), true, BWebResponse.Error_BadRequest_Code, "GET method is accepted. But received request method:  " + _Context.Request.HttpMethod);
            }

            if (!UrlParameters.TryGetValue("tenant", out string TenantName) || TenantName.Length == 0)
            {
                TenantName = DEFAULT_TENANT_NAME;
            }
            else TenantName = TenantName.ToLower();

            //Existing token from header
            string ClientAuthorization = null;
            if (BWebUtilities.DoesContextContainHeader(out List<string> ClientAuthorizationHeaderValues, out string _, _Context, "client-authorization"))
            {
                BUtility.CheckAndGetFirstStringFromList(ClientAuthorizationHeaderValues, out ClientAuthorization);
                if (ClientAuthorization != null && ClientAuthorization.Length == 0) ClientAuthorization = null;
            }

            //Existing token from url parameters
            //Note: Must be token type prepended. Example: ?existing_token=bearer%20abc123123
            if (!UrlParameters.TryGetValue("existing_token", out string ExistingToken) || ExistingToken.Length == 0)
            {
                ExistingToken = null;
            }
            else
            {
                ExistingToken = WebUtility.UrlDecode(ExistingToken);
            }

            //If both existing tokens are non-null; it is error
            if (ClientAuthorization != null && ExistingToken != null)
            {
                _ErrorMessageAction?.Invoke("Error: SSOLoginRequest: Both existing tokens from url parameters and headers are non-null.");

                return SSOCommon.MakeCallerRedirected(WebUtility.UrlDecode(RedirectUrlEncoded), true, BWebResponse.Error_BadRequest_Code, "Both existing tokens from url parameters and headers are non-null.");
            }

            //From now on, use ClientAuthorization; not ExistingToken
            if (ExistingToken != null)
            {
                ClientAuthorization = ExistingToken;
            }

            //Check and try refresh if expired
            if (ClientAuthorization != null
                && new Controller_SSOAccessToken(ClientAuthorization, DatabaseService, MemoryService, AzureAD_TenantID, AzureAD_AppID, AzureAD_ClientSecret, SSOSuperAdmins, _ErrorMessageAction)
                    .PerformCheckAndRefresh(
                        out Controller_SSOAccessToken.EPerformCheckAndRefreshSuccessStatus _,
                        out ClientAuthorization, 
                        out string UserID, 
                        out string _))
            {
                return SSOCommon.MakeCallerRedirected(WebUtility.UrlDecode(RedirectUrlEncoded), false, 0, null, UserID, ClientAuthorization);
            }

            string ServersideRedirectUrl = WebUtility.UrlEncode(ApiGatewayPublicUrl + "/auth/login/azure/callback");

            string AzureAuthenticationEndpointBase =
                $"https://login.microsoftonline.com/{AzureAD_TenantID}/oauth2/v2.0/authorize"
                + "?client_id=" + AzureAD_AppID
                + "&response_type=id_token code"
                + "&redirect_uri=" + ServersideRedirectUrl;

            var TrialCount = 0;
            string SSOStateUniqueID;
            BMemoryQueryParameters SSOStateUniqueID_QueryParameters;
            do
            {
                if (!BUtility.CalculateStringMD5(BUtility.RandomString(32, true), out SSOStateUniqueID, _ErrorMessageAction))
                {
                    return SSOCommon.MakeCallerRedirected(WebUtility.UrlDecode(RedirectUrlEncoded), true, 500, "SSO State ID generation has failed.");
                }

                SSOStateUniqueID_QueryParameters = SSOStateMEntry.ID_SSO_STATE_MEMORY_SERVICE_KEY(SSOStateUniqueID);

                if (!MemoryService.SetKeyValueConditionally(
                    SSOStateUniqueID_QueryParameters,
                    new Tuple<string, BPrimitiveType>(
                        SSOStateMEntry.HASH_KEY, 
                        new BPrimitiveType(JsonConvert.SerializeObject(
                            new SSOStateMEntry()
                            {
                                ServersideRedirectUrl = ServersideRedirectUrl,
                                TenantName = TenantName,
                                Status = SSOStateMEntry.STATUS_AUTHENTICATING
                            })
                        )
                    ),
                    _ErrorMessageAction))
                {
                    SSOStateUniqueID = null;
                }

            } while (SSOStateUniqueID == null && ++TrialCount < 5);
            
            if (SSOStateUniqueID == null)
            {
                return SSOCommon.MakeCallerRedirected(WebUtility.UrlDecode(RedirectUrlEncoded), true, 500, "Unique SSO State ID generation has failed.");
            }
            MemoryService.SetKeyExpireTime(SSOStateUniqueID_QueryParameters, TimeSpan.FromSeconds(120), _ErrorMessageAction);
    
            var AzureAuthenticationEndpoint = AzureAuthenticationEndpointBase
                + "&scope=" + SSOCommon.SCOPE_URL_ENCODED
                + "&response_mode=form_post"
                + "&nonce=" + SSOStateUniqueID
                + "&state="
                    + WebUtility.UrlEncode(
                        "redirect_url=" + RedirectUrlEncoded + 
                        "&tenant=" + TenantName + 
                        "&state=" + SSOStateUniqueID);

            return SSOCommon.MakeCallerRedirected(AzureAuthenticationEndpoint, false, 0, null);
        }
    }
}