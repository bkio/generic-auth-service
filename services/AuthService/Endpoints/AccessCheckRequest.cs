/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using AuthService.Endpoints.Common;
using AuthService.Endpoints.Controllers;
using AuthService.Endpoints.Structures;
using BCloudServiceUtilities;
using BCommonUtilities;
using BWebServiceUtilities;
using ServiceUtilities;
using ServiceUtilities.All;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AuthService.Endpoints
{
    internal class AccessCheckRequest : BppWebServiceBase
    {
        private readonly string AzureAD_AppID;
        private readonly string AzureAD_ClientSecret;

        private readonly IBDatabaseServiceInterface DatabaseService;
        private readonly IBMemoryServiceInterface MemoryService;

        private readonly List<string> SSOSuperAdmins;

        public AccessCheckRequest(
            IBDatabaseServiceInterface _DatabaseService,
            IBMemoryServiceInterface _MemoryService,
            string _AzureAD_AppID,
            string _AzureAD_ClientSecret,
            List<string> _SSOSuperAdmins)
        {
            DatabaseService = _DatabaseService;
            MemoryService = _MemoryService;

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

        private class AuthMethodToAccessMap_SuccessResponse
        {
            [JsonProperty("result")]
            public string Result;

            [JsonProperty(UserDBEntry.KEY_NAME_USER_ID)]
            public string UserID;

            [JsonProperty(UserDBEntry.USER_NAME_PROPERTY)]
            public string UserName;

            [JsonProperty(UserDBEntry.USER_EMAIL_PROPERTY)]
            public string UserEmail;

            [JsonProperty("authMethodKey")]
            public string AuthMethodKey;

            [JsonProperty("ssoTokenRefreshed")]
            public bool bSSOTokenRefreshed;

            [JsonProperty("newSSOTokenAfterRefresh")]
            public string NewSSOTokenAfterRefresh;
        }

        private BWebServiceResponse OnRequest_Internal(HttpListenerContext _Context, Action<string> _ErrorMessageAction = null)
        {
            if (_Context.Request.HttpMethod != "POST")
            {
                _ErrorMessageAction?.Invoke("AccessCheckRequest: POST method is accepted. But received request method:  " + _Context.Request.HttpMethod);
                return BWebResponse.MethodNotAllowed("POST method is accepted. But received request method: " + _Context.Request.HttpMethod);
            }

            string RequestPayload = null;
            JObject ParsedBody;
            using (var InputStream = _Context.Request.InputStream)
            {
                using var ResponseReader = new StreamReader(InputStream);
                try
                {
                    RequestPayload = ResponseReader.ReadToEnd();
                    ParsedBody = JObject.Parse(RequestPayload);
                }
                catch (Exception e)
                {
                    _ErrorMessageAction?.Invoke("AccessCheckRequest-> Malformed request body. Body content: " + RequestPayload + ", Exception: " + e.Message + ", Trace: " + e.StackTrace);
                    return BWebResponse.BadRequest("Malformed request body. Request must be a valid json form.");
                }
            }

            if (!ParsedBody.ContainsKey("forUrlPath") ||
                !ParsedBody.ContainsKey("requestMethod") ||
                !ParsedBody.ContainsKey("authorization"))
            {
                _ErrorMessageAction?.Invoke("AccessCheckRequest-> Request does not have required fields.");
                return BWebResponse.BadRequest("Request does not have required fields.");
            }

            return OnRequest_Internal_Recursive(false, ParsedBody, _ErrorMessageAction);
        }

        private BWebServiceResponse OnRequest_Internal_Recursive(
            bool bIsThisRetry,
            JObject ParsedBody,
            Action<string> _ErrorMessageAction)
        {
            var ForUrlPath = (string)ParsedBody["forUrlPath"];
            var RequestMethod = (string)ParsedBody["requestMethod"];

            var ScopeAccess = new List<AccessScope>();

            var SSOTokenRefreshStatus = Controller_SSOAccessToken.EPerformCheckAndRefreshSuccessStatus.None;
            var AccessTokenWithTokenType = (string)ParsedBody["authorization"];

            string Method;

            if (AccessTokenWithTokenType.StartsWith("Security"))
            {
                var QueryParameters = new BMemoryQueryParameters()
                {
                    Domain = Resources_DeploymentManager.Get().GetDeploymentBranchNameEscapedLoweredWithDash().ToUpper(),
                    SubDomain = "SELF_SIGNED_ACCESS_TOKEN_VALIDATION",
                    Identifier = AccessTokenWithTokenType
                };

                var MethodPrimitive = MemoryService.GetKeyValue(QueryParameters, "method", _ErrorMessageAction);
                if (MethodPrimitive == null)
                {
                    return BWebResponse.Unauthorized("Token is invalid. Please re-login.");
                }
                Method = MethodPrimitive.AsString;
            }
            else
            {
                var AccessTokenManager = new Controller_SSOAccessToken(AccessTokenWithTokenType, DatabaseService, MemoryService, AzureAD_AppID, AzureAD_ClientSecret, SSOSuperAdmins, _ErrorMessageAction);
                if (AccessTokenManager.PerformCheckAndRefresh(
                    out SSOTokenRefreshStatus,
                    out AccessTokenWithTokenType,
                    out _,
                    out string _EmailAddressWithoutPostfix))
                {
                    ParsedBody["authorization"] = AccessTokenWithTokenType;
                }
                else return BWebResponse.Unauthorized("Token is invalid. Please re-login.");

                if (!BUtility.CalculateStringMD5(AccessTokenWithTokenType, out string PasswordMD5FromToken, _ErrorMessageAction))
                {
                    return BWebResponse.InternalError("Hash operation failed.");
                }

                Method = _EmailAddressWithoutPostfix + Controller_SSOAccessToken.EMAIL_USER_NAME_POSTFIX + PasswordMD5FromToken;
            }

            if (!AuthenticationCommon.FetchFromMemoryService(MemoryService, Method, out string UserID, out string UserEmail, out string UserName, out ScopeAccess, _ErrorMessageAction))
            {
                if (!AuthenticationCommon.FetchFromDatabaseService(DatabaseService, MemoryService, Method, out UserID, out UserEmail, out UserName, out ScopeAccess, out BWebServiceResponse FailureResponse, _ErrorMessageAction))
                {
                    return FailureResponse;
                }
            }

            using (var Regexes = new StringWriter())
            {
                bool bAuthorized = false;
                foreach (var Access in ScopeAccess)
                {
                    string CurrentRegex = BUtility.WildCardToRegular(Access.WildcardPath);
                    Regexes.Write("\n\r" + CurrentRegex);

                    if (Regex.IsMatch(ForUrlPath, CurrentRegex))
                    {
                        switch (RequestMethod)
                        {
                            case "GET":
                                if (Access.AccessRights.Contains("GET")) bAuthorized = true;
                                break;
                            case "POST":
                                if (Access.AccessRights.Contains("POST")) bAuthorized = true;
                                break;
                            case "PUT":
                                if (Access.AccessRights.Contains("PUT")) bAuthorized = true;
                                break;
                            case "DELETE":
                                if (Access.AccessRights.Contains("DELETE")) bAuthorized = true;
                                break;
                            default:
                                break;
                        }
                    }
                    if (bAuthorized) break;
                }
                if (!bAuthorized)
                {
                    //Try to grant base access rights to to fix eventual consistency errors
                    if (!bIsThisRetry && Controller_Rights_Internal.Get().GrantBaseRightsToFinalRights(false, UserID, Method, _ErrorMessageAction))
                    {
                        return OnRequest_Internal_Recursive(true, ParsedBody, _ErrorMessageAction);
                    }
                    return BWebResponse.Forbidden("You do not have sufficient rights to access to the url.");
                }
            }

            return BWebResponse.StatusOK("User has access.", JObject.Parse(JsonConvert.SerializeObject(new AuthMethodToAccessMap_SuccessResponse()
            {
                Result = "success",
                UserID = UserID,
                UserName = UserName,
                UserEmail = UserEmail,
                AuthMethodKey = Method,
                bSSOTokenRefreshed = SSOTokenRefreshStatus == Controller_SSOAccessToken.EPerformCheckAndRefreshSuccessStatus.Refreshed,
                NewSSOTokenAfterRefresh = SSOTokenRefreshStatus == Controller_SSOAccessToken.EPerformCheckAndRefreshSuccessStatus.Refreshed ? AccessTokenWithTokenType : ""
            })));
        }
    }
}