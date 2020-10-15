using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using AuthService.Endpoints.Common;
using AuthService.Endpoints.Structures;
using BWebServiceUtilities;
using ServiceUtilities.All;
using Newtonsoft.Json.Linq;

namespace AuthService.Endpoints
{
    partial class InternalCalls
    {
        internal class DeleteTestUser : InternalWebServiceBase
        {
            public DeleteTestUser(string _InternalCallPrivateKey, int _ServerPort) : base(_InternalCallPrivateKey)
            {
                SetLocalServerPort(_ServerPort);
            }

            public static void SetLocalServerPort(int _Port)
            {
                LocalServerPort = _Port;
            }
            private static int LocalServerPort;

            protected override BWebServiceResponse Process(HttpListenerContext _Context, Action<string> _ErrorMessageAction = null)
            {
                if (_Context.Request.HttpMethod != "POST")
                {
                    _ErrorMessageAction?.Invoke("DeleteTestUser: POST method is accepted. But received request method:  " + _Context.Request.HttpMethod);
                    return BWebResponse.MethodNotAllowed("POST method is accepted. But received request method: " + _Context.Request.HttpMethod);
                }

                JObject ParsedBody;
                using (var InputStream = _Context.Request.InputStream)
                {
                    using (var ResponseReader = new StreamReader(InputStream))
                    {
                        try
                        {
                            ParsedBody = JObject.Parse(ResponseReader.ReadToEnd());
                        }
                        catch (Exception e)
                        {
                            _ErrorMessageAction?.Invoke("DeleteTestUser-> Read request body stage has failed. Exception: " + e.Message + ", Trace: " + e.StackTrace);
                            return BWebResponse.BadRequest("Malformed request body. Request must be a valid json form.");
                        }
                    }
                }

                if (!ParsedBody.ContainsKey(AuthDBEntry.USER_ID_PROPERTY))
                {
                    _ErrorMessageAction?.Invoke("DeleteTestUser-> Request does not have required fields.");
                    return BWebResponse.BadRequest("Request does not have required fields.");
                }

                var UserId = (string)ParsedBody[AuthDBEntry.USER_ID_PROPERTY];

                if (!DeleteUser(UserId, _ErrorMessageAction))
                {
                    return BWebResponse.InternalError("User delete process has been failed.");
                }

                return BWebResponse.StatusCreated("Test user has been deleted.", new JObject()
                {
                    [AuthDBEntry.USER_ID_PROPERTY] = UserId
                });
            }

            private bool DeleteUser(string _UserID, Action<string> _ErrorMessageAction, string _OptionalName = null)
            {
                var Endpoint = "http://localhost:" + LocalServerPort + "/auth/users/" + _UserID;

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
                    using var RequestTask = Client.DeleteAsync(Endpoint);
                    RequestTask.Wait();

                    using var Response = RequestTask.Result;
                    using var ResponseContent = Response.Content;

                    using var ReadResponseTask = ResponseContent.ReadAsStringAsync();
                    ReadResponseTask.Wait();

                    var ResponseString = ReadResponseTask.Result;

                    if (!Response.IsSuccessStatusCode)
                    {
                        _ErrorMessageAction?.Invoke("Error: DeleteTestUser->DeleteUser: Request returned error. Endpoint: " + Endpoint + ", code: " + Response.StatusCode + ", message: " + ResponseString);
                        return false;
                    }
                }
                catch (Exception e)
                {
                    if (e.InnerException != null && e.InnerException != e)
                    {
                        _ErrorMessageAction?.Invoke("Error: DeleteTestUser->DeleteUser->Inner: " + e.InnerException.Message + ", Trace: " + e.InnerException.StackTrace);
                    }
                    if (e is AggregateException)
                    {
                        foreach (var Inner in (e as AggregateException).InnerExceptions)
                        {
                            _ErrorMessageAction?.Invoke("Error: DeleteTestUser->DeleteUser->Aggregate->Inner: " + Inner.Message + ", Trace: " + Inner.StackTrace);
                        }
                    }
                    _ErrorMessageAction?.Invoke("Error: DeleteTestUser->DeleteUser: Request failed. Endpoint: " + Endpoint + ", message: " + e.Message + ", trace: " + e.StackTrace);
                    return false;
                }

                return true;
            }
        }
    }
}
