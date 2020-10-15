/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Threading;
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
    partial class InternalCalls
    {
        internal class SynchronizeUsersWithAzureAD : InternalWebServiceBase
        {
            private const string AuthScope = "https://graph.microsoft.com/.default";

            private readonly IBDatabaseServiceInterface DatabaseService;

            private readonly List<string> SSOSuperAdmins;

            private readonly string FetchUsersClientID;
            private readonly string FetchUsersClientSecret;
            private readonly string FetchUsersAppObjectID;

            private readonly string OAuth2TokenRequestUrl;

            public SynchronizeUsersWithAzureAD(
                string _InternalCallPrivateKey,
                string _AzureOAuth2TokenRequestUrl,
                string _AzureFetchUsersClientID, 
                string _AzureFetchUsersClientSecret, 
                string _AzureFetchUsersAppObjectID,
                IBDatabaseServiceInterface _DatabaseService,
                List<string> _SSOSuperAdmins) : base(_InternalCallPrivateKey)
            {
                FetchUsersClientID = _AzureFetchUsersClientID;
                FetchUsersClientSecret = _AzureFetchUsersClientSecret;
                FetchUsersAppObjectID = _AzureFetchUsersAppObjectID;

                OAuth2TokenRequestUrl = _AzureOAuth2TokenRequestUrl;

                DatabaseService = _DatabaseService;

                SSOSuperAdmins = _SSOSuperAdmins;
            }

            private struct UserPrincipal
            {
                [JsonProperty("userName")]
                public string Name;

                [JsonProperty("userEmail")]
                public string Email;
            }

            protected override BWebServiceResponse Process(HttpListenerContext _Context, Action<string> _ErrorMessageAction = null)
            {
                if (!GetTokenForAzure(out string TokenType, out string AccessToken, _ErrorMessageAction))
                {
                    return BWebResponse.InternalError("Acquiring access token from Azure has failed.");
                }

                if (!GetUserListFromAzure(out List<UserPrincipal> Users, TokenType, AccessToken, _ErrorMessageAction))
                {
                    return BWebResponse.InternalError("Acquiring user list from Azure has failed.");
                }

                if (!FindMissingUsersInDatabase(out List<UserPrincipal> UsersToBePut, Users, _ErrorMessageAction))
                {
                    return BWebResponse.InternalError("Acquiring difference in user list from Azure and system database has failed.");
                }

                foreach (var UserToBePut in UsersToBePut)
                {
                    if (!Controller_SSOAccessToken.RegisterUserAsPlaceholder(out string _, DatabaseService, UserToBePut.Email, UserToBePut.Name, SSOSuperAdmins, _ErrorMessageAction))
                    {
                        return BWebResponse.InternalError("Register user operation has failed.");
                    }
                }
                return BWebResponse.StatusOK("Ok.");
            }

            private bool FindMissingUsersInDatabase(out List<UserPrincipal> _UsersToBePut, List<UserPrincipal> _Users, Action<string> _ErrorMessageAction)
            {
                _UsersToBePut = null;

                var TmpDictionary = new Dictionary<string, UserPrincipal>();
                foreach (var AzureUser in _Users)
                {
                    TmpDictionary.Add(AzureUser.Email + Controller_SSOAccessToken.EMAIL_USER_NAME_POSTFIX, AzureUser);
                }

                if (!DatabaseService.ScanTable(
                    UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(),
                    out List<JObject> Result,
                    _ErrorMessageAction))
                {
                    _ErrorMessageAction?.Invoke("Scan unique-users-fields operation has failed.");
                    return false;
                }

                foreach (var Existing in Result)
                {
                    if (Existing.TryGetValue(UniqueUserFieldsDBEntry.KEY_NAME_USER_EMAIL, out JToken ExistingEmailToken)
                        && ExistingEmailToken.Type == JTokenType.String)
                    {
                        TmpDictionary.Remove((string)ExistingEmailToken); //TryRemove
                    }
                }

                _UsersToBePut = TmpDictionary.Values.ToList();
                return true;
            }

            private bool GetTokenForAzure(out string _TokenType, out string _AccessToken, Action<string> _ErrorMessageAction)
            {
                _TokenType = null;
                _AccessToken = null;

                var FormUrlEncodedPairs = new List<KeyValuePair<string, string>>()
                {
                    new KeyValuePair<string, string>("client_id", FetchUsersClientID),
                    new KeyValuePair<string, string>("scope", AuthScope),
                    new KeyValuePair<string, string>("grant_type", "client_credentials"),
                    new KeyValuePair<string, string>("client_secret", FetchUsersClientSecret)
                };

                using var Handler = new HttpClientHandler
                {
                    SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls11 | SslProtocols.Tls,
                    ServerCertificateCustomValidationCallback = (a, b, c, d) => true
                };
                using var Client = new HttpClient(Handler);
                Client.DefaultRequestHeaders.TryAddWithoutValidation("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");

                string ResponseString = "";
                try
                {
                    using var RequestContent = new FormUrlEncodedContent(FormUrlEncodedPairs);
                    using var RequestTask = Client.PostAsync(OAuth2TokenRequestUrl, RequestContent);
                    RequestTask.Wait();

                    using var Response = RequestTask.Result;
                    using var ResponseContent = Response.Content;

                    using var ReadResponseTask = ResponseContent.ReadAsStringAsync();
                    ReadResponseTask.Wait();

                    ResponseString = ReadResponseTask.Result;

                    if (!Response.IsSuccessStatusCode)
                    {
                        _ErrorMessageAction?.Invoke("GetTokenForAzure->Error: " + ResponseString);
                        return false;
                    }

                    var Parsed = JObject.Parse(ResponseString);
                    if (!Parsed.TryGetValue("token_type", out JToken TokenType) || TokenType.Type != JTokenType.String
                        || !Parsed.TryGetValue("access_token", out JToken AccessToken) || AccessToken.Type != JTokenType.String)
                    {
                        _ErrorMessageAction?.Invoke("GetTokenForAzure->Error: Unexpected response: " + ResponseString);
                        return false;
                    }

                    _TokenType = (string)TokenType;
                    _AccessToken = (string)AccessToken;
                }
                catch (Exception e)
                {
                    if (e.InnerException != null && e.InnerException != e)
                    {
                        _ErrorMessageAction?.Invoke("GetTokenForAzure->Error: Inner: " + e.InnerException.Message + ", Trace: " + e.InnerException.StackTrace);
                    }
                    if (e is AggregateException)
                    {
                        foreach (var Inner in (e as AggregateException).InnerExceptions)
                        {
                            _ErrorMessageAction?.Invoke("GetTokenForAzure->Error: Aggregate->Inner: " + Inner.Message + ", Trace: " + Inner.StackTrace);
                        }
                    }
                    _ErrorMessageAction?.Invoke("GetTokenForAzure->Error: " + ResponseString + ", message: " + e.Message + ", trace: " + e.StackTrace);
                    return false;
                }
                return true;
            }

            private bool GetUserListFromAzure(out List<UserPrincipal> _Users, string _TokenType, string _AccessToken, Action<string> _ErrorMessageAction)
            {
                _Users = null;

                using var Handler = new HttpClientHandler
                {
                    SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls11 | SslProtocols.Tls,
                    ServerCertificateCustomValidationCallback = (a, b, c, d) => true
                };
                using var Client = new HttpClient(Handler);
                Client.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", _TokenType + " " + _AccessToken);

                string ResponseString = "";
                try
                {
                    using var RequestTask = Client.GetAsync("https://graph.microsoft.com/v1.0/servicePrincipals/" + FetchUsersAppObjectID + "/appRoleAssignedTo");
                    RequestTask.Wait();

                    using var Response = RequestTask.Result;
                    using var ResponseContent = Response.Content;

                    using var ReadResponseTask = ResponseContent.ReadAsStringAsync();
                    ReadResponseTask.Wait();

                    ResponseString = ReadResponseTask.Result;

                    if (!Response.IsSuccessStatusCode)
                    {
                        _ErrorMessageAction?.Invoke("GetUserListFromAzure->Error: " + ResponseString);
                        return false;
                    }

                    var Parsed = JObject.Parse(ResponseString);

                    if (!Parsed.TryGetValue("value", out JToken Values) || Values.Type != JTokenType.Array)
                    {
                        _ErrorMessageAction?.Invoke("GetTokenForAzure->Error: Unexpected response: " + ResponseString);
                        return false;
                    }

                    var UsersResult = new List<UserPrincipal>();

                    var ValuesArray = Values as JArray;

                    var InternalFailure = new BValue<bool>(false, EBProducerStatus.MultipleProducer);
                    var WaitFor = new ManualResetEvent(false);
                    var RemainedTasks = new ConcurrentStack<bool>();
                    for (var i = 0; i < ValuesArray.Count; i++)
                        RemainedTasks.Push(true);

                    foreach (var Value in ValuesArray)
                    {
                        if (Value.Type != JTokenType.Object)
                        {
                            _ErrorMessageAction?.Invoke("GetTokenForAzure->Error: Unexpected response: " + ResponseString);
                            return false;
                        }
                        var ValueObject = (JObject)Value;

                        if (!ValueObject.TryGetValue("principalDisplayName", out JToken UserNameToken) || UserNameToken.Type != JTokenType.String
                            || !ValueObject.TryGetValue("principalId", out JToken PrincipleIDToken) || PrincipleIDToken.Type != JTokenType.String)
                        {
                            _ErrorMessageAction?.Invoke("GetTokenForAzure->Error: Unexpected response: " + ResponseString);
                            return false;
                        }

                        var UserName = (string)UserNameToken;
                        var PrincipalId = (string)PrincipleIDToken;

                        BTaskWrapper.Run(() =>
                        {
                            if (!GetUserEmail(out string UserEmail, PrincipalId, _TokenType, _AccessToken, _ErrorMessageAction))
                            {
                                InternalFailure.Set(true);
                                WaitFor.Set();
                                return;
                            }

                            if (InternalFailure.Get()) return;

                            lock (UsersResult)
                            {
                                UsersResult.Add(new UserPrincipal()
                                {
                                    Name = UserName,
                                    Email = UserEmail
                                });
                            }

                            RemainedTasks.TryPop(out bool _);
                            if (RemainedTasks.Count == 0)
                            {
                                WaitFor.Set();
                            }
                        });
                    }

                    if (ValuesArray.Count > 0)
                    {
                        try { WaitFor.WaitOne(); } catch (Exception) { }
                    }
                    try { WaitFor.Close(); } catch (Exception) { }

                    if (InternalFailure.Get())
                    {
                        _ErrorMessageAction?.Invoke("GetUserListFromAzure->Error: Get user e-mail step has failed.");
                        return false;
                    }

                    _Users = UsersResult;
                }
                catch (Exception e)
                {
                    if (e.InnerException != null && e.InnerException != e)
                    {
                        _ErrorMessageAction?.Invoke("GetUserListFromAzure->Error: Inner: " + e.InnerException.Message + ", Trace: " + e.InnerException.StackTrace);
                    }
                    if (e is AggregateException)
                    {
                        foreach (var Inner in (e as AggregateException).InnerExceptions)
                        {
                            _ErrorMessageAction?.Invoke("GetUserListFromAzure->Error: Aggregate->Inner: " + Inner.Message + ", Trace: " + Inner.StackTrace);
                        }
                    }
                    _ErrorMessageAction?.Invoke("GetUserListFromAzure->Error: " + ResponseString + ", message: " + e.Message + ", trace: " + e.StackTrace);
                    return false;
                }
                return true;
            }

            private bool GetUserEmail(out string _Email, string _PrincipalId, string _TokenType, string _AccessToken, Action<string> _ErrorMessageAction)
            {
                _Email = null;

                using var Handler = new HttpClientHandler
                {
                    SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls11 | SslProtocols.Tls,
                    ServerCertificateCustomValidationCallback = (a, b, c, d) => true
                };
                using var Client = new HttpClient(Handler);
                Client.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", _TokenType + " " + _AccessToken);

                string ResponseString = "";
                try
                {
                    using var RequestTask = Client.GetAsync("https://graph.microsoft.com/v1.0/users/" + _PrincipalId + "/mail");
                    RequestTask.Wait();

                    using var Response = RequestTask.Result;
                    using var ResponseContent = Response.Content;

                    using var ReadResponseTask = ResponseContent.ReadAsStringAsync();
                    ReadResponseTask.Wait();

                    ResponseString = ReadResponseTask.Result;

                    if (!Response.IsSuccessStatusCode)
                    {
                        _ErrorMessageAction?.Invoke("GetUserEmail->Error: " + ResponseString);
                        return false;
                    }

                    var Parsed = JObject.Parse(ResponseString);

                    if (!Parsed.TryGetValue("value", out JToken EmailToken) || EmailToken.Type != JTokenType.String)
                    {
                        _ErrorMessageAction?.Invoke("GetUserEmail->Error: Unexpected response: " + ResponseString);
                        return false;
                    }

                    _Email = ((string)EmailToken).ToLower();
                }
                catch (Exception e)
                {
                    if (e.InnerException != null && e.InnerException != e)
                    {
                        _ErrorMessageAction?.Invoke("GetUserEmail->Error: Inner: " + e.InnerException.Message + ", Trace: " + e.InnerException.StackTrace);
                    }
                    if (e is AggregateException)
                    {
                        foreach (var Inner in (e as AggregateException).InnerExceptions)
                        {
                            _ErrorMessageAction?.Invoke("GetUserEmail->Error: Aggregate->Inner: " + Inner.Message + ", Trace: " + Inner.StackTrace);
                        }
                    }
                    _ErrorMessageAction?.Invoke("GetUserEmail->Error: " + ResponseString + ", message: " + e.Message + ", trace: " + e.StackTrace);
                    return false;
                }
                return true;
            }
        }
    }
}