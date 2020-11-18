/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Text;
using System.Text.RegularExpressions;
using AuthService.Endpoints.Common;
using AuthService.Endpoints.Structures;
using BCloudServiceUtilities;
using BCommonUtilities;
using BWebServiceUtilities;
using ServiceUtilities;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AuthService.Endpoints.Controllers
{
    public class Controller_SSOAccessToken
    {
        public const string EMAIL_USER_NAME_POSTFIX = ".sso";

        private readonly IBDatabaseServiceInterface DatabaseService;
        private readonly IBMemoryServiceInterface MemoryService;

        public readonly string AccessToken_TokenTypeSpacePrepended;
        private readonly string AccessToken_WithoutTokenType;

        private readonly string AzureAD_AppID;
        private readonly string AzureAD_ClientSecret;

        private readonly Action<string> ErrorMessageAction;

        private readonly List<string> SSOSuperAdmins;

        private Controller_SSOAccessToken() { }
        public Controller_SSOAccessToken(
            string _AccessToken_TokenTypeSpacePrepended,
            IBDatabaseServiceInterface _DatabaseService,
            IBMemoryServiceInterface _MemoryService,
            string _AzureAD_AppID,
            string _AzureAD_ClientSecret,
            List<string> _SSOSuperAdmins,
            Action<string> _ErrorMessageAction = null)
        {
            AccessToken_TokenTypeSpacePrepended = _AccessToken_TokenTypeSpacePrepended;

            DatabaseService = _DatabaseService;
            MemoryService = _MemoryService;

            AzureAD_AppID = _AzureAD_AppID;
            AzureAD_ClientSecret = _AzureAD_ClientSecret;

            SSOSuperAdmins = _SSOSuperAdmins;

            int SpaceIx = AccessToken_TokenTypeSpacePrepended.IndexOf(' ');
            if (SpaceIx < 0)
            {
                throw new ArgumentException("Invalid _AccessToken_TokenTypeSpacePrepended. It must contain the token type.");
            }
            AccessToken_WithoutTokenType = AccessToken_TokenTypeSpacePrepended.Substring(SpaceIx + 1);

            ErrorMessageAction = _ErrorMessageAction;
        }

        public static void SetLocalServerPort(int _Port)
        {
            LocalServerPort = _Port;
        }
        private static int LocalServerPort;

        public bool RegisterUser(out string _UserID, string _RefreshToken, int _ExpiresInSeconds)
        {
            _UserID = null;

            if (!ValidateAccessTokenSyntax(out string EmailWithoutPostfix, out string OptionalName)) return false;

            if (!MakeQueryParameters(out BMemoryQueryParameters QueryParameters, out string _PasswordMD5_FromAccessToken)) return false;

            JArray NewBaseRights;

            if (SSOSuperAdmins.Contains(EmailWithoutPostfix))
            {
                if (!CreateUser(out _UserID, out _, DatabaseService, EmailWithoutPostfix, OptionalName, ErrorMessageAction)) return false;
                NewBaseRights = new JArray()
                {
                    JObject.Parse(JsonConvert.SerializeObject(
                    new AccessScope()
                    {
                        WildcardPath = "*",
                        AccessRights = new List<string>() { "GET", "POST", "PUT", "DELETE" }
                    }))
                };
            }
            else if (!CreateUser(out _UserID, out NewBaseRights, DatabaseService, EmailWithoutPostfix, OptionalName, ErrorMessageAction)) return false;

            if (!CreateAuthMethod(out string _AccessMethod, _UserID, EmailWithoutPostfix, _PasswordMD5_FromAccessToken, ErrorMessageAction)) return false;

            if (!Controller_Rights_Internal.Get().GrantUserWithRights(false, _UserID, NewBaseRights, ErrorMessageAction)) return false;

            long ExpiresAt = new DateTimeOffset(DateTime.UtcNow.AddSeconds(_ExpiresInSeconds)).ToUnixTimeSeconds();

            MemoryService.SetKeyValue(
                QueryParameters,
                new Tuple<string, BPrimitiveType>[]
                {
                    new Tuple<string, BPrimitiveType>(UserDBEntry.KEY_NAME_USER_ID, new BPrimitiveType(_UserID)),
                    new Tuple<string, BPrimitiveType>("refresh_token", new BPrimitiveType(_RefreshToken)),
                    new Tuple<string, BPrimitiveType>("expires_at", new BPrimitiveType(ExpiresAt))
                },
                ErrorMessageAction);
            MemoryService.SetKeyExpireTime(QueryParameters, TimeSpan.FromDays(7), ErrorMessageAction);

            return true;
        }

        public static bool RegisterUserAsPlaceholder(out string _UserID, IBDatabaseServiceInterface _DatabaseService, string _EmailWithoutPrefix, string _Name, List<string> _SSOSuperAdmins, Action<string> _ErrorMessageAction)
        {
            JArray NewBaseRights;

            if (_SSOSuperAdmins.Contains(_EmailWithoutPrefix))
            {
                if (!CreateUser(out _UserID, out _, _DatabaseService, _EmailWithoutPrefix, _Name, _ErrorMessageAction)) return false;
                NewBaseRights = new JArray()
                {
                    JObject.Parse(JsonConvert.SerializeObject(
                    new AccessScope()
                    {
                        WildcardPath = "*",
                        AccessRights = new List<string>() { "GET", "POST", "PUT", "DELETE" }
                    }))
                };
            }
            else if (!CreateUser(out _UserID, out NewBaseRights, _DatabaseService, _EmailWithoutPrefix, _Name, _ErrorMessageAction)) return false;

            if (!Controller_Rights_Internal.Get().GrantUserWithRights(false, _UserID, NewBaseRights, _ErrorMessageAction)) return false;

            return true;
        }

        public bool RegisterAuthMethodAndMemoryEntryAfterRefresh(string _UserID, string _EmailAddressWithoutPostfix, int _ExpiresInSeconds, string _NewRefreshToken)
        {
            if (!MakeQueryParameters(out BMemoryQueryParameters QueryParameters, out string _PasswordMD5_FromAccessToken)) return false;

            JArray NewBaseRights;
            if (SSOSuperAdmins.Contains(_EmailAddressWithoutPostfix))
            {
                NewBaseRights = new JArray()
                {
                    JObject.Parse(JsonConvert.SerializeObject(
                    new AccessScope()
                    {
                        WildcardPath = "*",
                        AccessRights = new List<string>() { "GET", "POST", "PUT", "DELETE" }
                    }))
                };
            }
            else if (!TryGettingBaseRightsOrDefault(out NewBaseRights, _UserID, ErrorMessageAction)) return false;

            if (!CreateAuthMethod(out string _AccessMethod, _UserID, _EmailAddressWithoutPostfix, _PasswordMD5_FromAccessToken, ErrorMessageAction)) return false;

            if (!Controller_Rights_Internal.Get().GrantUserWithRights(false, _UserID, NewBaseRights, ErrorMessageAction)) return false;

            long ExpiresAt = new DateTimeOffset(DateTime.UtcNow.AddSeconds(_ExpiresInSeconds)).ToUnixTimeSeconds();

            MemoryService.SetKeyValue(
                QueryParameters,
                new Tuple<string, BPrimitiveType>[]
                {
                    new Tuple<string, BPrimitiveType>(UserDBEntry.KEY_NAME_USER_ID, new BPrimitiveType(_UserID)),
                    new Tuple<string, BPrimitiveType>("refresh_token", new BPrimitiveType(_NewRefreshToken)),
                    new Tuple<string, BPrimitiveType>("expires_at", new BPrimitiveType(ExpiresAt))
                },
                ErrorMessageAction);
            MemoryService.SetKeyExpireTime(QueryParameters, TimeSpan.FromDays(7), ErrorMessageAction);

            return true;
        }

        public bool CheckTokenExpiry(out string _UserID, out bool _bExpired, out string _RefreshToken)
        {
            _UserID = null;
            _bExpired = false;
            _RefreshToken = null;

            if (!MakeQueryParameters(out BMemoryQueryParameters QueryParameters, out string _PasswordMD5_FromAccessToken)) return false;

            _bExpired = IsTokenExpiredOrInvalid(out Dictionary<string, BPrimitiveType> Result, MemoryService, QueryParameters, ErrorMessageAction);

            if (Result == null)
            {
                return false;
            }

            _UserID = Result[UserDBEntry.KEY_NAME_USER_ID].AsString;
            _RefreshToken = Result["refresh_token"].AsString;

            return true;
        }

        public static bool IsTokenExpiredOrInvalid(out Dictionary<string, BPrimitiveType> _Result, IBMemoryServiceInterface _MemoryService, BMemoryQueryParameters _QueryParameters, Action<string> _ErrorMessageAction)
        {
            _Result = _MemoryService.GetKeysValues(_QueryParameters,
                new List<string>()
                {
                    UserDBEntry.KEY_NAME_USER_ID,
                    "refresh_token",
                    "expires_at"

                }, _ErrorMessageAction);

            if (_Result == null) return true;
            if (!_Result.ContainsKey(UserDBEntry.KEY_NAME_USER_ID) || !_Result.ContainsKey("refresh_token") || !_Result.ContainsKey("expires_at"))
            {
                var DebugString = "";
                foreach (var Returned in _Result)
                {
                    DebugString += Returned.Key + "->" + Returned.Value.ToString();
                }
                _ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->IsTokenExpiredOrInvalid: MemoryService.GetKeysValues did not return all mandatory fields. Deleting the entry. Returned: " + DebugString);
                _MemoryService.DeleteAllKeys(_QueryParameters, true, _ErrorMessageAction);
                _Result = null;

                return true;
            }
            if(_Result["expires_at"].AsInteger <= new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds())
            {
                return true;
            }
            return false;
        }

        public void TryDeletingAuthMethodAndMemoryEntry(string _UserID, string _EmailAddressWithoutPostfix)
        {
            if (MakeQueryParameters(out BMemoryQueryParameters QueryParameters, out string _PasswordMD5_FromAccessToken))
            {
                MemoryService.DeleteAllKeys(QueryParameters, true, ErrorMessageAction);
            }
            DeleteSSOAuthMethod(_UserID, false, _EmailAddressWithoutPostfix, _PasswordMD5_FromAccessToken, ErrorMessageAction);
        }

        public bool TryRefreshingAccessToken(
            out Controller_SSOAccessToken _NewAccessTokenManager, 
            out string _NewRefreshToken, 
            out int _NewExpiresInSeconds, 
            string _RefreshToken)
        {
            _NewAccessTokenManager = null;
            _NewRefreshToken = null;
            _NewExpiresInSeconds = 0;

            var FormUrlEncodedPairs = new List<KeyValuePair<string, string>>()
            {
                new KeyValuePair<string, string>("client_id", AzureAD_AppID),
                new KeyValuePair<string, string>("scope", SSOCommon.SCOPE),
                new KeyValuePair<string, string>("grant_type", "refresh_token"),
                new KeyValuePair<string, string>("refresh_token", _RefreshToken),
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
                using var RequestTask = Client.PostAsync("https://login.microsoftonline.com/common/oauth2/v2.0/token", RequestContent);
                RequestTask.Wait();

                using var Response = RequestTask.Result;
                using var ResponseContent = Response.Content;

                using var ReadResponseTask = ResponseContent.ReadAsStringAsync();
                ReadResponseTask.Wait();

                ResponseString = ReadResponseTask.Result;

                if (!Response.IsSuccessStatusCode)
                {
                    ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->TryRefreshingAccessToken: " + ResponseString);
                    return false;
                }

                var Parsed = JObject.Parse(ResponseString);

                _NewAccessTokenManager = new Controller_SSOAccessToken(
                    (string)Parsed["token_type"] + (char)32 + (string)Parsed["access_token"],
                    DatabaseService,
                    MemoryService,
                    AzureAD_AppID,
                    AzureAD_ClientSecret,
                    SSOSuperAdmins,
                    ErrorMessageAction);

                _NewRefreshToken = (string)Parsed["refresh_token"];
                _NewExpiresInSeconds = (int)Parsed["expires_in"];
            }
            catch (Exception e)
            {
                if (e.InnerException != null && e.InnerException != e)
                {
                    ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->TryRefreshingAccessToken->Inner: " + e.InnerException.Message + ", Trace: " + e.InnerException.StackTrace);
                }
                if (e is AggregateException)
                {
                    foreach (var Inner in (e as AggregateException).InnerExceptions)
                    {
                        ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->TryRefreshingAccessToken->Aggregate->Inner: " + Inner.Message + ", Trace: " + Inner.StackTrace);
                    }
                }
                ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->TryRefreshingAccessToken: " + ResponseString + ", message: " + e.Message + ", trace: " + e.StackTrace);
                return false;
            }

            return true;
        }

        private static bool CreateUser(out string _UserID, out JArray _BaseRightsOrDefault, IBDatabaseServiceInterface _DatabaseService, string _EmailWithoutPostfix, string _OptionalName, Action<string> _ErrorMessageAction)
        {
            _UserID = null;
            _BaseRightsOrDefault = null;

            var EmailAddressWithPostfix = _EmailWithoutPostfix + EMAIL_USER_NAME_POSTFIX;

            var Endpoint = "http://localhost:" + LocalServerPort + "/auth/users";

            using var Handler = new HttpClientHandler
            {
                SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls11 | SslProtocols.Tls,
                ServerCertificateCustomValidationCallback = (a, b, c, d) => true
            };
            using var Client = new HttpClient(Handler);
            Client.DefaultRequestHeaders.TryAddWithoutValidation("internal-call-secret", CommonData.INTERNAL_CALL_PRIVATE_KEY);
            Client.DefaultRequestHeaders.TryAddWithoutValidation("do-not-get-db-clearance", "false");
            try
            {
                using var RequestContent = new StringContent(new JObject()
                {
                    [UserDBEntry.USER_EMAIL_PROPERTY] = EmailAddressWithPostfix,
                    [UserDBEntry.USER_NAME_PROPERTY] = _OptionalName != null ? (_OptionalName + EMAIL_USER_NAME_POSTFIX) : EmailAddressWithPostfix

                }.ToString(), Encoding.UTF8, "application/json");

                using var RequestTask = Client.PutAsync(Endpoint, RequestContent);
                RequestTask.Wait();

                using var Response = RequestTask.Result;
                using var ResponseContent = Response.Content;

                using var ReadResponseTask = ResponseContent.ReadAsStringAsync();
                ReadResponseTask.Wait();

                var ResponseString = ReadResponseTask.Result;

                if (!Response.IsSuccessStatusCode)
                {
                    if ((int)Response.StatusCode == BWebResponse.Error_Conflict_Code)
                    {
                        if (!_DatabaseService.GetItem(
                            UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(),
                            UniqueUserFieldsDBEntry.KEY_NAME_USER_EMAIL,
                            new BPrimitiveType(EmailAddressWithPostfix),
                            UniqueUserFieldsDBEntry.Properties,
                            out JObject _ExistenceCheck,
                           _ErrorMessageAction)) return false;

                        _UserID = (string)_ExistenceCheck[UserDBEntry.KEY_NAME_USER_ID];

                        if (!TryGettingBaseRightsOrDefault(out _BaseRightsOrDefault, _UserID, _ErrorMessageAction))
                        {
                            _ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->CreateUser: TryGettingBaseRightsOrDefault has failed.");
                            return false;
                        }

                        return true;
                    }
                    _ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->CreateUser: Request returned error. Endpoint: " + Endpoint + ", code: " + Response.StatusCode + ", message: " + ResponseString);
                    return false;
                }

                _UserID = (string)JObject.Parse(ResponseString)[UserDBEntry.KEY_NAME_USER_ID];
                if (!Controller_Rights_Internal.Get().GetUserDefaultRights(out _BaseRightsOrDefault, _UserID, _ErrorMessageAction))
                {
                    _ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->CreateUser: GetUserDefaultRights has failed.");
                    return false;
                }
            }
            catch (Exception e)
            {
                if (e.InnerException != null && e.InnerException != e)
                {
                    _ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->CreateUser->Inner: " + e.InnerException.Message + ", Trace: " + e.InnerException.StackTrace);
                }
                if (e is AggregateException)
                {
                    foreach (var Inner in (e as AggregateException).InnerExceptions)
                    {
                        _ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->CreateUser->Aggregate->Inner: " + Inner.Message + ", Trace: " + Inner.StackTrace);
                    }
                }
                _ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->CreateUser: Request failed. Endpoint: " + Endpoint + ", message: " + e.Message + ", trace: " + e.StackTrace);
                return false;
            }
            return true;
        }

        private static bool CreateAuthMethod(out string _AccessMethod, string _UserID, string _EmailWithoutPostfix, string _PasswordMD5_FromAccessToken, Action<string> _ErrorMessageAction)
        {
            var EmailAddressWithPostfix = _EmailWithoutPostfix + EMAIL_USER_NAME_POSTFIX;

            _AccessMethod = EmailAddressWithPostfix + _PasswordMD5_FromAccessToken;

            var Endpoint = "http://localhost:" + LocalServerPort + "/auth/users/" + _UserID + "/access_methods";

            using var Handler = new HttpClientHandler
            {
                SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls11 | SslProtocols.Tls,
                ServerCertificateCustomValidationCallback = (a, b, c, d) => true
            };
            using var Client = new HttpClient(Handler);
            Client.DefaultRequestHeaders.TryAddWithoutValidation("internal-call-secret", CommonData.INTERNAL_CALL_PRIVATE_KEY);
            Client.DefaultRequestHeaders.TryAddWithoutValidation("do-not-get-db-clearance", "false");
            try
            {
                using var RequestContent = new StringContent(JsonConvert.SerializeObject(
                    new AuthMethod()
                    {
                        Method = AuthMethod.Methods.USER_EMAIL_PASSWORD_METHOD,
                        UserEmail = EmailAddressWithPostfix,
                        PasswordMD5 = _PasswordMD5_FromAccessToken
                        
                    }), Encoding.UTF8, "application/json");

                using var RequestTask = Client.PutAsync(Endpoint, RequestContent);
                RequestTask.Wait();

                using var Response = RequestTask.Result;
                if (!Response.IsSuccessStatusCode)
                {
                    if ((int)Response.StatusCode == BWebResponse.Error_Conflict_Code) //Already exists
                    {
                        _ErrorMessageAction?.Invoke("Warning: Controller_SSOAccessToken->CreateAuthMethod: Conflicting auth method upon call to URL: " + Endpoint);
                        return true;
                    }

                    using var ResponseContent = Response.Content;

                    using var ReadResponseTask = ResponseContent.ReadAsStringAsync();
                    ReadResponseTask.Wait();

                    var ResponseString = ReadResponseTask.Result;

                    _ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->CreateAuthMethod: Request returned error. Endpoint: " + Endpoint + ", code: " + Response.StatusCode + ", message: " + ResponseString);
                    return false;
                }
            }
            catch (Exception e)
            {
                if (e.InnerException != null && e.InnerException != e)
                {
                    _ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->CreateAuthMethod->Inner: " + e.InnerException.Message + ", Trace: " + e.InnerException.StackTrace);
                }
                if (e is AggregateException)
                {
                    foreach (var Inner in (e as AggregateException).InnerExceptions)
                    {
                        _ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->CreateAuthMethod->Aggregate->Inner: " + Inner.Message + ", Trace: " + Inner.StackTrace);
                    }
                }
                _ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->CreateAuthMethod: Request failed. Endpoint: " + Endpoint + ", message: " + e.Message + ", trace: " + e.StackTrace);
                return false;
            }
            return true;
        }

        public static bool TryGettingBaseRightsOrDefault(out JArray _BaseRightsOrDefault, string _UserID, Action<string> _ErrorMessageAction)
        {
            if (!Controller_Rights_Internal.Get().GetUserDefaultRights(out _BaseRightsOrDefault, _UserID, _ErrorMessageAction))
            {
                return false;
            }

            if (!GetUserBaseRights(_UserID, out JArray _ExistingBaseRights, _ErrorMessageAction))
            {
                return false;
            }

            AccessScopeLibrary.UnionMergeRights(_BaseRightsOrDefault, _ExistingBaseRights);
            return true;
        }

        private static bool GetUserBaseRights(string _UserID, out JArray _UserBaseRights, Action<string> _ErrorMessageAction)
        {
            _UserBaseRights = null;

            var Endpoint = "http://localhost:" + LocalServerPort + "/auth/users/" + _UserID + "/base_access_rights";

            using var Handler = new HttpClientHandler
            {
                SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls11 | SslProtocols.Tls,
                ServerCertificateCustomValidationCallback = (a, b, c, d) => true
            };
            using var Client = new HttpClient(Handler);
            Client.DefaultRequestHeaders.TryAddWithoutValidation("internal-call-secret", CommonData.INTERNAL_CALL_PRIVATE_KEY);
            Client.DefaultRequestHeaders.TryAddWithoutValidation("do-not-get-db-clearance", "false");

            try
            {
                using var RequestTask = Client.GetAsync(Endpoint);
                RequestTask.Wait();

                using var Response = RequestTask.Result;
                using var ResponseContent = Response.Content;

                using var ReadResponseTask = ResponseContent.ReadAsStringAsync();
                ReadResponseTask.Wait();

                var ResponseString = ReadResponseTask.Result;

                if (!Response.IsSuccessStatusCode)
                {
                    _ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->GetUserBaseRights: Request returned error. Endpoint: " + Endpoint + ", code: " + Response.StatusCode + ", message: " + ResponseString);
                    return false;
                }

                _UserBaseRights = (JArray)(JObject.Parse(ResponseString)[UserDBEntry.BASE_ACCESS_SCOPE_PROPERTY]);
                return true;
            }
            catch (Exception e)
            {
                if (e.InnerException != null && e.InnerException != e)
                {
                    _ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->GetUserBaseRights->Inner: " + e.InnerException.Message + ", Trace: " + e.InnerException.StackTrace);
                }
                if (e is AggregateException)
                {
                    foreach (var Inner in (e as AggregateException).InnerExceptions)
                    {
                        _ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->GetUserBaseRights->Aggregate->Inner: " + Inner.Message + ", Trace: " + Inner.StackTrace);
                    }
                }
                _ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->GetUserBaseRights: Request failed. Endpoint: " + Endpoint + ", message: " + e.Message + ", trace: " + e.StackTrace);
            }

            return false;
        }
        
        public static bool GetSSOAuthMethods(out bool _bInternalErrorOccured, out List<AuthMethod> _SSOMethods, string _UserID, Action<string> _ErrorMessageAction)
        {
            _bInternalErrorOccured = false;
            _SSOMethods = null;

            var Endpoint = "http://localhost:" + LocalServerPort + "/auth/users/" + _UserID + "/access_methods";

            using var Handler = new HttpClientHandler
            {
                SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls11 | SslProtocols.Tls,
                ServerCertificateCustomValidationCallback = (a, b, c, d) => true
            };
            using var Client = new HttpClient(Handler);
            Client.DefaultRequestHeaders.TryAddWithoutValidation("internal-call-secret", CommonData.INTERNAL_CALL_PRIVATE_KEY);
            Client.DefaultRequestHeaders.TryAddWithoutValidation("do-not-get-db-clearance", "false");
            try
            {
                using var RequestTask = Client.GetAsync(Endpoint);
                RequestTask.Wait();

                using var Response = RequestTask.Result;
                using var ResponseContent = Response.Content;

                using var ReadResponseTask = ResponseContent.ReadAsStringAsync();
                ReadResponseTask.Wait();

                var ResponseString = ReadResponseTask.Result;

                if (!Response.IsSuccessStatusCode)
                {
                    _bInternalErrorOccured = (int)Response.StatusCode == BWebResponse.Error_InternalError_Code;
                    _ErrorMessageAction?.Invoke("Error: SSOAccessTokenValidation->GetSSOAuthMethods: Request returned error. Endpoint: " + Endpoint + ", code: " + Response.StatusCode + ", message: " + ResponseString);
                    return false;
                }

                _SSOMethods = new List<AuthMethod>();

                var AuthMethods = (JArray)(JObject.Parse(ResponseString)[UserDBEntry.AUTH_METHODS_PROPERTY]);
                foreach (var Current in AuthMethods)
                {
                    var Method = (JObject)Current;
                    var Deserialized = JsonConvert.DeserializeObject<AuthMethod>(Current.ToString());
                    if (Deserialized.Method == AuthMethod.Methods.USER_EMAIL_PASSWORD_METHOD
                        && Deserialized.UserEmail.EndsWith(EMAIL_USER_NAME_POSTFIX))
                    {
                        _SSOMethods.Add(Deserialized);
                    }
                }
            }
            catch (Exception e)
            {
                if (e.InnerException != null && e.InnerException != e)
                {
                    _ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->GetSSOAuthMethods->Inner: " + e.InnerException.Message + ", Trace: " + e.InnerException.StackTrace);
                }
                if (e is AggregateException)
                {
                    foreach (var Inner in (e as AggregateException).InnerExceptions)
                    {
                        _ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->GetSSOAuthMethods->Aggregate->Inner: " + Inner.Message + ", Trace: " + Inner.StackTrace);
                    }
                }
                _bInternalErrorOccured = true;
                _ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->GetSSOAuthMethods: Request failed. Endpoint: " + Endpoint + ", message: " + e.Message + ", trace: " + e.StackTrace);
                return false;
            }
            return true;
        }

        public static bool DeleteSSOAuthMethod(string _UserID, bool _bDoNotGetDBClearance, string _EmailWithoutPostfix, string _PasswordMD5_FromAccessToken, Action<string> _ErrorMessageAction)
        {
            var EmailAddressWithPostfix = _EmailWithoutPostfix + EMAIL_USER_NAME_POSTFIX;

            var AccessMethod = EmailAddressWithPostfix + _PasswordMD5_FromAccessToken;

            var Endpoint = "http://localhost:" + LocalServerPort + "/auth/users/" + _UserID + "/access_methods/" + WebUtility.UrlEncode(AccessMethod);

            using var Handler = new HttpClientHandler
            {
                SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls11 | SslProtocols.Tls,
                ServerCertificateCustomValidationCallback = (a, b, c, d) => true
            };
            using var Client = new HttpClient(Handler);
            Client.DefaultRequestHeaders.TryAddWithoutValidation("internal-call-secret", CommonData.INTERNAL_CALL_PRIVATE_KEY);
            Client.DefaultRequestHeaders.TryAddWithoutValidation("do-not-get-db-clearance", _bDoNotGetDBClearance == true ? "true" : "false");
            try
            {
                using var RequestTask = Client.DeleteAsync(Endpoint);
                RequestTask.Wait();

                using var Response = RequestTask.Result;
                if (!Response.IsSuccessStatusCode)
                {
                    using var ResponseContent = Response.Content;

                    using var ReadResponseTask = ResponseContent.ReadAsStringAsync();
                    ReadResponseTask.Wait();

                    var ResponseString = ReadResponseTask.Result;

                    _ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->DeleteAuthMethod: Request returned error. Endpoint: " + Endpoint + ", code: " + Response.StatusCode + ", message: " + ResponseString);
                    return false;
                }
            }
            catch (Exception e)
            {
                if (e.InnerException != null && e.InnerException != e)
                {
                    _ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->DeleteSSOAuthMethod->Inner: " + e.InnerException.Message + ", Trace: " + e.InnerException.StackTrace);
                }
                if (e is AggregateException)
                {
                    foreach (var Inner in (e as AggregateException).InnerExceptions)
                    {
                        _ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->DeleteSSOAuthMethod->Aggregate->Inner: " + Inner.Message + ", Trace: " + Inner.StackTrace);
                    }
                }
                _ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->DeleteSSOAuthMethod: Request failed. Endpoint: " + Endpoint + ", message: " + e.Message + ", trace: " + e.StackTrace);
                return false;
            }
            return true;
        }
        
        public bool ValidateAccessTokenSyntax(out string _EmailWithoutPostfix, out string _OptionalName)
        {
            _EmailWithoutPostfix = "";
            _OptionalName = "";

            var JWTHandler = new JwtSecurityTokenHandler();
            JwtSecurityToken Token = null;
            try
            {
                Token = JWTHandler.ReadJwtToken(AccessToken_WithoutTokenType);
            }
            catch (Exception e)
            {
                ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->ValidateAccessToken: Unable to read the access token. Message: " + e.Message + ", trace: " + e.StackTrace);
                return false;
            }
            if (Token.Payload == null)
            {
                ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->ValidateAccessToken: Payload is null. Token: " + Token?.ToString());
                return false;
            }

            bool bContains_email = Token.Payload.ContainsKey("email");
            bool bContains_upn = Token.Payload.ContainsKey("upn");
            bool bContains_unique_name = Token.Payload.ContainsKey("unique_name");

            if (!bContains_email && !bContains_upn && !bContains_unique_name)
            {
                ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->ValidateAccessToken: Access token has been decoded. But it does not contain e-mail information. Payload: " + GetPayloadPrintString(Token.Payload));
                return false;
            }

            if (((bContains_email && IsValidEmailAddress(_EmailWithoutPostfix = (string)Token.Payload["email"]))
                || (bContains_upn && IsValidEmailAddress(_EmailWithoutPostfix = (string)Token.Payload["upn"]))
                || (bContains_unique_name && IsValidEmailAddress(_EmailWithoutPostfix = (string)Token.Payload["unique_name"]))) == false)
            {
                _EmailWithoutPostfix = "";
                ErrorMessageAction?.Invoke("Error: Controller_SSOAccessToken->ValidateAccessToken: Access token has been decoded. But it does not contain a valid e-mail information. Payload: " + GetPayloadPrintString(Token.Payload));
                return false;
            }

            if (Token.Payload.ContainsKey("name"))
            {
                _OptionalName = (string)Token.Payload["name"];
            }

            _EmailWithoutPostfix = _EmailWithoutPostfix.ToLower();

            return true;
        }

        public enum EPerformCheckAndRefreshSuccessStatus
        {
            None,
            AlreadyValid,
            Refreshed
        }
        public bool PerformCheckAndRefresh(out EPerformCheckAndRefreshSuccessStatus _SuccessStatus, out string _NewAccessTokenWithTokenType, out string _UserID, out string _EmailAddressWithoutPostfix)
        {
            _SuccessStatus = EPerformCheckAndRefreshSuccessStatus.None;

            _UserID = null;

            _NewAccessTokenWithTokenType = AccessToken_TokenTypeSpacePrepended;

            if (!ValidateAccessTokenSyntax(out _EmailAddressWithoutPostfix, out string _)) return false;

            var bCheckResult = CheckTokenExpiry(out _UserID, out bool _bExpired, out string _RefreshToken);
            if (!bCheckResult || _bExpired)
            {
                if (_UserID == null || _RefreshToken == null) return false;

                TryDeletingAuthMethodAndMemoryEntry(_UserID, _EmailAddressWithoutPostfix);
                    
                if (!TryRefreshingAccessToken(out Controller_SSOAccessToken AccessTokenManager, out string NewRefreshToken, out int ExpiresInSeconds, _RefreshToken))
                {
                    return false;
                }

                if (!AccessTokenManager.RegisterAuthMethodAndMemoryEntryAfterRefresh(_UserID, _EmailAddressWithoutPostfix, ExpiresInSeconds, NewRefreshToken))
                {
                    AccessTokenManager.TryDeletingAuthMethodAndMemoryEntry(_UserID, _EmailAddressWithoutPostfix); //Again, in case some are managed to be registered.
                    return false;
                }

                _NewAccessTokenWithTokenType = AccessTokenManager.AccessToken_TokenTypeSpacePrepended;
                _SuccessStatus = EPerformCheckAndRefreshSuccessStatus.Refreshed;
            }
            else _SuccessStatus = EPerformCheckAndRefreshSuccessStatus.AlreadyValid;

            return true;
        }

        public static BMemoryQueryParameters MakeSSOQueryParameters(string _PasswordMD5_FromAccessToken)
        {
            return new BMemoryQueryParameters()
            {
                Domain = Resources_DeploymentManager.Get().GetDeploymentBranchNameEscapedLoweredWithDash().ToUpper(),
                SubDomain = "SSO_ACCESS_TOKEN_VALIDATION",
                Identifier = _PasswordMD5_FromAccessToken
            };
        }

        private bool MakeQueryParameters(out BMemoryQueryParameters _QueryParameters, out string _PasswordMD5_FromAccessToken)
        {
            _QueryParameters = new BMemoryQueryParameters();
            if (!BUtility.CalculateStringMD5(AccessToken_TokenTypeSpacePrepended, out _PasswordMD5_FromAccessToken, ErrorMessageAction)) return false;

            _QueryParameters = MakeSSOQueryParameters(_PasswordMD5_FromAccessToken);
            return true;
        }

        private static string GetPayloadPrintString(JwtPayload _Payload)
        {
            var Result = "";

            foreach (var Current in _Payload)
            {
                Result += Current.Key + " -> " + Current.Value + "\n"; 
            }
            Result.TrimEnd('\n');

            return Result;
        }

        private const string EmailRegexVal = @"\A(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)\Z";
        private static bool IsValidEmailAddress(string _Field)
        {
            return Regex.IsMatch(_Field, EmailRegexVal, RegexOptions.IgnoreCase);
        }
    }
}