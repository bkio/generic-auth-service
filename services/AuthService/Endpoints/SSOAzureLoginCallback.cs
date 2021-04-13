/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using AuthService.Endpoints.Common;
using AuthService.Endpoints.Controllers;
using AuthService.Endpoints.Structures;
using BCloudServiceUtilities;
using BCommonUtilities;
using BWebServiceUtilities;
using ServiceUtilities.All;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AuthService.Endpoints
{
    internal class SSOAzureLoginCallback : BppWebServiceBase
    {
        private readonly string AzureAD_TenantID;
        private readonly string AzureAD_AppID;
        private readonly string AzureAD_ClientSecret;

        private readonly IBDatabaseServiceInterface DatabaseService;
        private readonly IBMemoryServiceInterface MemoryService;

        private readonly List<string> SSOSuperAdmins;

        public SSOAzureLoginCallback(
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
            //Azure sends a GET request in case user does not have access set from Integral.
            if (_Context.Request.HttpMethod == "GET")
            {
                if (!UrlParameters.TryGetValue("redirect_url", out string RedirectUrlEncoded) || RedirectUrlEncoded.Length == 0)
                {
                    RedirectUrlEncoded = SSOAzureLoginRequest.DEFAULT_REDIRECT_URL_ENCODED;
                }

                return SSOCommon.MakeCallerRedirected(WebUtility.UrlDecode(RedirectUrlEncoded), true, BWebResponse.Error_Unauthorized_Code, "You do not have access to this service.");
            }

            if (_Context.Request.HttpMethod != "POST")
            {
                _ErrorMessageAction?.Invoke("SSOLoginCallback: POST method is accepted. But received request method:  " + _Context.Request.HttpMethod);
                return BWebResponse.MethodNotAllowed("POST method is accepted. But received request method: " + _Context.Request.HttpMethod);
            }

            string ResponseContent = null;
            try
            {
                using (var InputStream = _Context.Request.InputStream)
                {
                    using (var ResponseReader = new StreamReader(InputStream))
                    {
                        ResponseContent = ResponseReader.ReadToEnd();
                    }
                }
            }
            catch (Exception e) 
            {
                _ErrorMessageAction?.Invoke("Error: SSOLoginCallback: Error occured during request body read. Message: " + e.Message + ", trace: " + e.StackTrace);
                return BWebResponse.BadRequest("Request body must be provided correctly.");
            }

            if (ResponseContent == null)
            {
                return BWebResponse.BadRequest("Request body must be provided.");
            }
            
            if (!Parse_FirstLeg_Authentication_Content(
                ResponseContent,
                out string AuthorizationCode_From_FirstLeg,
                out BMemoryQueryParameters SSOStateUniqueID_QueryParameters,
                out SSOStateMEntry SSOState,
                out string LocalRedirectUrl_From_FirstLeg,
                out string EmailAddress_From_FirstLeg,
                out string AzureADUniqueID_From_FirstLeg,
                out BWebServiceResponse FailureResponse, 
                _ErrorMessageAction))
            {
                return SSOCommon.MakeCallerRedirected(LocalRedirectUrl_From_FirstLeg, true, FailureResponse.StatusCode, FailureResponse.ResponseContent.String);
            }

            if (!Perform_SecondLeg_Authorization(
                AuthorizationCode_From_FirstLeg,
                SSOStateUniqueID_QueryParameters,
                SSOState,
                out AuthorizationResult SuccessResponse,
                out FailureResponse,
                _ErrorMessageAction))
            {
                return SSOCommon.MakeCallerRedirected(LocalRedirectUrl_From_FirstLeg, true, FailureResponse.StatusCode, FailureResponse.ResponseContent.String);
            }
            
            //Like: Bearer [accessToken]
            var NewAuthorizationField = SuccessResponse.TokenType + (char)32 + SuccessResponse.AccessToken;

            var AccessTokenManager = new Controller_SSOAccessToken(NewAuthorizationField, DatabaseService, MemoryService, AzureAD_TenantID, AzureAD_AppID, AzureAD_ClientSecret, SSOSuperAdmins, _ErrorMessageAction);
            if (!AccessTokenManager.RegisterUser(out string _UserID, SuccessResponse.RefreshToken, SuccessResponse.ExpiresInSeconds))
            {
                return SSOCommon.MakeCallerRedirected(LocalRedirectUrl_From_FirstLeg, true, 500, "User registration has failed.");
            }

            return SSOCommon.MakeCallerRedirected(LocalRedirectUrl_From_FirstLeg, false, 0, null, _UserID, NewAuthorizationField);
        }

        private bool Parse_FirstLeg_Authentication_Content(
            string _ResponseContent, 
            out string _AuthorizationCode_From_FirstLeg,
            out BMemoryQueryParameters _SSOStateUniqueID_QueryParameters,
            out SSOStateMEntry _SSOState,
            out string _LocalRedirectUrl_From_FirstLeg,
            out string _EmailAddress_From_FirstLeg, 
            out string _AzureADUniqueID_From_FirstLeg, 
            out BWebServiceResponse _FailureResponse, 
            Action<string> _ErrorMessageAction)
        {
            _AuthorizationCode_From_FirstLeg = null;
            _SSOStateUniqueID_QueryParameters = new BMemoryQueryParameters();
            _SSOState = null;
            _LocalRedirectUrl_From_FirstLeg = null;
            _EmailAddress_From_FirstLeg = null;
            _AzureADUniqueID_From_FirstLeg = null;
            _FailureResponse = BWebResponse.InternalError("");

            _ResponseContent = _ResponseContent.Trim();

            //Handle error
            if (_ResponseContent.StartsWith("error="))
            {
                var ErrorResponse = new JObject()
                {
                    ["result"] = "failure"
                };
                try
                {
                    var ErrorFields = _ResponseContent.Split('&');
                    if (ErrorFields != null && ErrorFields.Length >= 2)
                    {
                        ErrorResponse["error"] = ErrorFields[0].Substring("error=".Length);
                        ErrorResponse["message"] = ErrorFields[1].Substring("error_description=".Length);
                    }
                }
                catch (Exception) { }

                _FailureResponse = BWebResponse.Unauthorized(ErrorResponse.ToString());
                return false;
            }

            //Normal flow
            var Splitted = _ResponseContent.Split('&');
            if (Splitted == null || Splitted.Length < 3)
            {
                _FailureResponse = BWebResponse.BadRequest("Request body must contain all requested types. Split has failed.");
                return false;
            }

            string IDToken = null;
            string StateField = null;
            for (var i = 0; i < Splitted.Length; i++)
            {
                if (Splitted[i].StartsWith("id_token=")) IDToken = Splitted[i].Substring("id_token=".Length);
                else if (Splitted[i].StartsWith("code=")) _AuthorizationCode_From_FirstLeg = Splitted[i].Substring("code=".Length);
                else if (Splitted[i].StartsWith("state=")) StateField = WebUtility.UrlDecode(Splitted[i].Substring("state=".Length));
            }
            if (IDToken == null || _AuthorizationCode_From_FirstLeg == null || StateField == null)
            {
                _FailureResponse = BWebResponse.BadRequest("Request body must contain all requested types.");
                return false;
            }

            Splitted = StateField.Split('&');
            if (Splitted == null || Splitted.Length < 3)
            {
                _FailureResponse = BWebResponse.BadRequest("State field must contain all mandatory entries. Split has failed.");
                return false;
            }

            bool bSSOStateUniqueID_QueryParameters_Set = false;
            string TenantName = null;
            for (var i = 0; i < Splitted.Length; i++)
            {
                if (Splitted[i].StartsWith("redirect_url=")) _LocalRedirectUrl_From_FirstLeg = WebUtility.UrlDecode(Splitted[i].Substring("redirect_url=".Length));
                else if (Splitted[i].StartsWith("tenant=")) TenantName = Splitted[i].Substring("tenant=".Length);
                else if (Splitted[i].StartsWith("state="))
                {
                    _SSOStateUniqueID_QueryParameters = SSOStateMEntry.ID_SSO_STATE_MEMORY_SERVICE_KEY(Splitted[i].Substring("state=".Length));
                    bSSOStateUniqueID_QueryParameters_Set = true;
                }
            }
            if (_LocalRedirectUrl_From_FirstLeg == null || TenantName == null || !bSSOStateUniqueID_QueryParameters_Set)
            {
                _FailureResponse = BWebResponse.BadRequest("State field must contain all mandatory entries.");
                return false;
            }

            var Serialized = MemoryService.GetKeyValue(_SSOStateUniqueID_QueryParameters, SSOStateMEntry.HASH_KEY, _ErrorMessageAction);
            if (Serialized == null)
            {
                _FailureResponse = BWebResponse.Unauthorized("Login prompt session has expired. Please try again.");
                return false;
            }
            try
            {
                _SSOState = JsonConvert.DeserializeObject<SSOStateMEntry>(Serialized.AsString);
                if (_SSOState == null) throw new NullReferenceException();
            }
            catch (Exception e)
            {
                _ErrorMessageAction?.Invoke("Error: SSOLoginCallback->Parse_FirstLeg_Authentication_Content: Invalid session state. Message: " + e.Message + ", trace: " + e.StackTrace);
                _FailureResponse = BWebResponse.InternalError("Invalid session state. Please try again.");
                return false;
            }
            if (_SSOState.Status != SSOStateMEntry.STATUS_AUTHENTICATING)
            {
                _FailureResponse = BWebResponse.Unauthorized("Invalid SSO state. Please try again.");
                return false;
            }
            if (TenantName != _SSOState.TenantName)
            {
                _FailureResponse = BWebResponse.Unauthorized("SSO state - request tenant mismatch. Please try again.");
                return false;
            }
            
            var JWTHandler = new JwtSecurityTokenHandler();
            JwtSecurityToken Token = null;
            try
            {
                Token = JWTHandler.ReadJwtToken(IDToken);
            }
            catch (Exception e)
            {
                _ErrorMessageAction?.Invoke("Error: SSOLoginCallback->Parse_FirstLeg_Authentication_Content: Invalid JWT token. Token: " + IDToken + ", message: " + e.Message + ", trace: " + e.StackTrace);
                _FailureResponse = BWebResponse.BadRequest("Invalid JWT token.");
                return false;
            }

            if (!Token.Payload.TryGetValue("email", out object EmailObject))
            {
                _FailureResponse = BWebResponse.BadRequest("JWT token does not contain email in the payload.");
                return false;
            }

            _EmailAddress_From_FirstLeg = ((string)EmailObject).ToLower();

            if (!Token.Payload.TryGetValue("sub", out object AzureADUserUniqueIDObject))
            {
                _FailureResponse = BWebResponse.BadRequest("JWT token does not contain sub in the payload.");
                return false;
            }
            _AzureADUniqueID_From_FirstLeg = ((string)AzureADUserUniqueIDObject).ToLower();

            return true;
        }

        private class AuthorizationResult
        {
            public string TokenType;
            public string AccessToken;
            public int ExpiresInSeconds;
            public string RefreshToken;
        }
        private bool Perform_SecondLeg_Authorization(
            string _AuthorizationCode_From_FirstLeg,
            BMemoryQueryParameters _SSOStateUniqueID_QueryParameters,
            SSOStateMEntry _SSOState,
            out AuthorizationResult _SuccessResponse,
            out BWebServiceResponse _FailureResponse,
            Action<string> _ErrorMessageAction)
        {
            _SuccessResponse = null;
            _FailureResponse = BWebResponse.InternalError("");

            _SSOState.Status = SSOStateMEntry.STATUS_AUTHORIZING;
            MemoryService.SetKeyValue(_SSOStateUniqueID_QueryParameters,
                new Tuple<string, BPrimitiveType>[]
                {
                    new Tuple<string, BPrimitiveType>(SSOStateMEntry.HASH_KEY, new BPrimitiveType(JsonConvert.SerializeObject(_SSOState)))
                },
                _ErrorMessageAction);
            MemoryService.SetKeyExpireTime(_SSOStateUniqueID_QueryParameters, TimeSpan.FromSeconds(120), _ErrorMessageAction);

            var FormUrlEncodedPairs = new List<KeyValuePair<string, string>>()
            {
                new KeyValuePair<string, string>("client_id", AzureAD_AppID),
                new KeyValuePair<string, string>("scope", SSOCommon.SCOPE),
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("code", _AuthorizationCode_From_FirstLeg),
                new KeyValuePair<string, string>("redirect_uri", WebUtility.UrlDecode(_SSOState.ServersideRedirectUrl)),
                new KeyValuePair<string, string>("client_secret", WebUtility.UrlDecode(AzureAD_ClientSecret))
            };

            using var Handler = new HttpClientHandler
            {
                SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls11 | SslProtocols.Tls,
                ServerCertificateCustomValidationCallback = (a, b, c, d) => true
            };
            using var Client = new HttpClient(Handler);
            Client.DefaultRequestHeaders.TryAddWithoutValidation("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");

            string ResponseString = null;
            try
            {
                using var RequestContent = new FormUrlEncodedContent(FormUrlEncodedPairs);
                using var RequestTask = Client.PostAsync($"https://login.microsoftonline.com/{AzureAD_TenantID}/oauth2/v2.0/token", RequestContent);
                RequestTask.Wait();

                using var Response = RequestTask.Result;
                using var ResponseContent = Response.Content;

                using var ReadResponseTask = ResponseContent.ReadAsStringAsync();
                ReadResponseTask.Wait();

                ResponseString = ReadResponseTask.Result;

                if (!Response.IsSuccessStatusCode)
                {
                    bool bJsonParseable = true;
                    try { JObject.Parse(ResponseString); } catch (JsonReaderException) { bJsonParseable = false; }

                    _FailureResponse = new BWebServiceResponse(
                        (int)Response.StatusCode,
                        new BStringOrStream(ResponseString),
                        bJsonParseable ? "application/json" : "text/html");
                    return false;
                }

                var Parsed = JObject.Parse(ResponseString);
                _SuccessResponse = new AuthorizationResult()
                {
                    TokenType = (string)Parsed["token_type"],
                    AccessToken = (string)Parsed["access_token"],
                    ExpiresInSeconds = (int)Parsed["expires_in"],
                    RefreshToken = (string)Parsed["refresh_token"]
                };
            }
            catch (Exception e)
            {
                if (e.InnerException != null && e.InnerException != e)
                {
                    _ErrorMessageAction?.Invoke("Error: SSOLoginCallback->Perform_SecondLeg_Authorization->Inner: " + e.InnerException.Message + ", Trace: " + e.InnerException.StackTrace);
                }
                if (e is AggregateException)
                {
                    foreach (var Inner in (e as AggregateException).InnerExceptions)
                    {
                        _ErrorMessageAction?.Invoke("Error: SSOLoginCallback->Perform_SecondLeg_Authorization->Aggregate->Inner: " + Inner.Message + ", Trace: " + Inner.StackTrace);
                    }
                }
                _ErrorMessageAction?.Invoke("Error: SSOLoginCallback->Perform_SecondLeg_Authorization: Authorization request failed. Response: " + ResponseString + ", message: " + e.Message + ", trace: " + e.StackTrace);
                _FailureResponse = BWebResponse.InternalError("Authorization request has failed.");
                return false;
            }

            MemoryService.DeleteAllKeys(_SSOStateUniqueID_QueryParameters, true, _ErrorMessageAction);

            return true;
        }
    }
}