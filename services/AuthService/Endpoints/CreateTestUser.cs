/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System;
using System.Net;
using System.Text;
using System.Net.Http;
using System.Security.Authentication;
using System.Collections.Generic;
using AuthService.Endpoints.Controllers;
using AuthService.Endpoints.Common;
using AuthService.Endpoints.Structures;
using BCloudServiceUtilities;
using BCommonUtilities;
using BWebServiceUtilities;
using ServiceUtilities;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AuthService.Endpoints
{
    partial class InternalCalls
    {
        internal class CreateTestUser : InternalWebServiceBaseTimeoutable
        {
            private readonly IBDatabaseServiceInterface DatabaseService;
            private readonly int LocalServerPort;
            private readonly string RootPath;

            public CreateTestUser(string _InternalCallPrivateKey, IBDatabaseServiceInterface _DatabaseService, int _LocalServerPort, string _RootPath) : base(_InternalCallPrivateKey)
            {
                DatabaseService = _DatabaseService;
                LocalServerPort = _LocalServerPort;
                RootPath = _RootPath;
            }

            public override BWebServiceResponse OnRequest_Interruptable(HttpListenerContext _Context, Action<string> _ErrorMessageAction = null)
            {
                if (_Context.Request.HttpMethod != "POST")
                {
                    _ErrorMessageAction?.Invoke("CreateTestUser: POST method is accepted. But received request method:  " + _Context.Request.HttpMethod);
                    return BWebResponse.MethodNotAllowed("POST method is accepted. But received request method: " + _Context.Request.HttpMethod);
                }

                return OnRequest_CreateTestUser(_Context, _ErrorMessageAction);
            }

            private BWebServiceResponse OnRequest_CreateTestUser(HttpListenerContext _Context, Action<string> _ErrorMessageAction)
            {
                string OptionalName = BUtility.RandomString(12, true) + "_test";
                string EmailWithoutPostfix = OptionalName + "@test.com";

                var AccumulatedSSOMethodRightsOrDefault = new JArray()
                {
                    JObject.Parse(JsonConvert.SerializeObject(
                    new AccessScope()
                    {
                        WildcardPath = "*",
                        AccessRights = new List<string>() { "GET", "POST", "PUT", "DELETE" }
                    }))
                };

                if (!CreateUser(out string _UserID, EmailWithoutPostfix, _ErrorMessageAction, OptionalName))
                {
                    return BWebResponse.InternalError("User creation process has been failed.");
                }

                if (!CreateAuthMethod(out string _ApiKey, _UserID, _ErrorMessageAction))
                {
                    return BWebResponse.InternalError("Auth method creation process has been failed.");
                }

                if (!Controller_Rights_Internal.Get().GrantUserWithRights(false, _UserID, AccumulatedSSOMethodRightsOrDefault, _ErrorMessageAction))
                {
                    return BWebResponse.InternalError("Grant user with rights process has been failed.");
                }
                
                return BWebResponse.StatusCreated("User has been created.", new JObject()
                {
                    [UserDBEntry.KEY_NAME_USER_ID] = _UserID,
                    [AuthMethod.API_KEY_PROPERTY] = _ApiKey,
                    [AuthMethod.USER_EMAIL_PROPERTY] = EmailWithoutPostfix
                });
            }

            private bool CreateUser(out string _UserID, string _EmailWithoutPostfix, Action<string> _ErrorMessageAction, string _OptionalName = null)
            {
                _UserID = null;

                var Endpoint = "http://localhost:" + LocalServerPort + RootPath + "auth/users";

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
                        [UserDBEntry.USER_EMAIL_PROPERTY] = _EmailWithoutPostfix,
                        [UserDBEntry.USER_NAME_PROPERTY] = _OptionalName != null ? _OptionalName : _EmailWithoutPostfix

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
                            if (!DatabaseService.GetItem(
                                UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(),
                                UniqueUserFieldsDBEntry.KEY_NAME_USER_EMAIL,
                                new BPrimitiveType(_EmailWithoutPostfix),
                                UniqueUserFieldsDBEntry.Properties,
                                out JObject _ExistenceCheck,
                               _ErrorMessageAction)) return false;

                            _UserID = (string)_ExistenceCheck[UserDBEntry.KEY_NAME_USER_ID];

                            return true;
                        }
                        _ErrorMessageAction?.Invoke("Error: CreateTestUser->CreateUser: Request returned error. Endpoint: " + Endpoint + ", code: " + Response.StatusCode + ", message: " + ResponseString);
                        return false;
                    }

                    _UserID = (string)JObject.Parse(ResponseString)[UserDBEntry.KEY_NAME_USER_ID];
                }
                catch (Exception e)
                {
                    if (e.InnerException != null && e.InnerException != e)
                    {
                        _ErrorMessageAction?.Invoke("Error: CreateTestUser->CreateUser->Inner: " + e.InnerException.Message + ", Trace: " + e.InnerException.StackTrace);
                    }
                    if (e is AggregateException)
                    {
                        foreach (var Inner in (e as AggregateException).InnerExceptions)
                        {
                            _ErrorMessageAction?.Invoke("Error: CreateTestUser->CreateUser->Aggregate->Inner: " + Inner.Message + ", Trace: " + Inner.StackTrace);
                        }
                    }
                    _ErrorMessageAction?.Invoke("Error: CreateTestUser->CreateUser: Request failed. Endpoint: " + Endpoint + ", message: " + e.Message + ", trace: " + e.StackTrace);
                    return false;
                }
                return true;
            }

            private bool CreateAuthMethod(out string _ApiKey, string _UserID, Action<string> _ErrorMessageAction)
            {
                _ApiKey = null;

                var Endpoint = "http://localhost:" + LocalServerPort + RootPath + "auth/users/" + _UserID + "/access_methods";

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
                            Method = AuthMethod.Methods.API_KEY_METHOD

                        }), Encoding.UTF8, "application/json");

                    using var RequestTask = Client.PutAsync(Endpoint, RequestContent);
                    RequestTask.Wait();

                    using var Response = RequestTask.Result;
                    using var ResponseContent = Response.Content;

                    using var ReadResponseTask = ResponseContent.ReadAsStringAsync();
                    ReadResponseTask.Wait();

                    string ResponseString = ReadResponseTask.Result;
                    if (Response.IsSuccessStatusCode)
                    {
                        var Parsed = JObject.Parse(ResponseString);
                        JObject Immutable_NewAccessMethod_JObject = JObject.Parse(JsonConvert.SerializeObject(Parsed["newAccessMethod"]));
                        _ApiKey = (string) Immutable_NewAccessMethod_JObject["apiKey"];
                    }
                    else
                    {
                        if ((int)Response.StatusCode == BWebResponse.Error_Conflict_Code) //Already exists
                        {
                            _ErrorMessageAction?.Invoke("Warning: CreateTestUser->CreateAuthMethod: Conflicting auth method upon call to URL: " + Endpoint);
                            return true;
                        }

                        _ErrorMessageAction?.Invoke("Error: CreateTestUser->CreateAuthMethod: Request returned error. Endpoint: " + Endpoint + ", code: " + Response.StatusCode + ", message: " + ResponseString);
                        return false;
                    }
                }
                catch (Exception e)
                {
                    if (e.InnerException != null && e.InnerException != e)
                    {
                        _ErrorMessageAction?.Invoke("Error: CreateTestUser->CreateAuthMethod->Inner: " + e.InnerException.Message + ", Trace: " + e.InnerException.StackTrace);
                    }
                    if (e is AggregateException)
                    {
                        foreach (var Inner in (e as AggregateException).InnerExceptions)
                        {
                            _ErrorMessageAction?.Invoke("Error: CreateTestUser->CreateAuthMethod->Aggregate->Inner: " + Inner.Message + ", Trace: " + Inner.StackTrace);
                        }
                    }
                    _ErrorMessageAction?.Invoke("Error: CreateTestUser->CreateAuthMethod: Request failed. Endpoint: " + Endpoint + ", message: " + e.Message + ", trace: " + e.StackTrace);
                    return false;
                }

                return true;
            }
        }
    }
}