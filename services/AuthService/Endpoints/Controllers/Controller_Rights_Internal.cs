/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Text;
using System.Threading.Tasks;
using AuthService.Endpoints.Common;
using AuthService.Endpoints.Structures;
using BCloudServiceUtilities;
using BWebServiceUtilities;
using BWebServiceUtilities_GC;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AuthService.Endpoints.Controllers
{
    public class Controller_Rights_Internal
    {
        private Controller_Rights_Internal() { }
        public static Controller_Rights_Internal Get()
        {
            if (Instance == null)
            {
                Instance = new Controller_Rights_Internal();
            }
            return Instance;
        }
        private static Controller_Rights_Internal Instance = null;

        public void SetLocalServerPort(int _Port)
        {
            LocalServerPort = _Port;
        }
        private int LocalServerPort;

        public void SetMemoryService(IBMemoryServiceInterface _MemoryService)
        {
            MemoryService = _MemoryService;
        }
        private IBMemoryServiceInterface MemoryService = null;

        public bool GetUserDefaultRights(out JArray _Result, string _UserID, Action<string> _ErrorMessageAction)
        {
            _Result = null;

            if (!PerformGetRequestToGetGloballySharedModelIds(out List<string> GloballySharedModelIDs, _ErrorMessageAction))
            {
                return false;
            }

            _Result = new JArray()
            {
                JObject.Parse(JsonConvert.SerializeObject(
                    new AccessScope()
                    {
                        WildcardPath = "/auth/users/" + _UserID,
                        AccessRights = new List<string>() { "GET", "POST" }
                    })),
                JObject.Parse(JsonConvert.SerializeObject(
                    new AccessScope()
                    {
                        WildcardPath = "/auth/users/" + _UserID + "/*",
                        AccessRights = new List<string>() { "GET", "POST", "PUT", "DELETE" }
                    })),
                JObject.Parse(JsonConvert.SerializeObject(
                    new AccessScope()
                    {
                        WildcardPath = "/auth/list_registered_email_addresses",
                        AccessRights = new List<string>() { "GET" }
                    })),
                JObject.Parse(JsonConvert.SerializeObject(
                    new AccessScope()
                    {
                        WildcardPath = "/3d/models",
                        AccessRights = new List<string>() { "PUT" }
                    })),
                JObject.Parse(JsonConvert.SerializeObject(
                    new AccessScope()
                    {
                        WildcardPath = "/3d/models/globally_shared",
                        AccessRights = new List<string>() { "GET" }
                    })),
                JObject.Parse(JsonConvert.SerializeObject(
                    new AccessScope()
                    {
                        WildcardPath = "/3d/models/get_models_by/user_id/" + _UserID + "/*",
                        AccessRights = new List<string>() { "GET" }
                    })),
                JObject.Parse(JsonConvert.SerializeObject(
                    new AccessScope()
                    {
                        WildcardPath = "/custom_procedures/by_user/" + _UserID + "/*",
                        AccessRights = new List<string>() { "POST" }
                    }))
            };

            foreach (var ModelId in GloballySharedModelIDs)
            {
                _Result.Add(JObject.Parse(JsonConvert.SerializeObject(
                new AccessScope()
                {
                    WildcardPath = "/3d/models/" + ModelId + "*",
                    AccessRights = new List<string>() { "GET" } //Only view access
                })));
                _Result.Add(JObject.Parse(JsonConvert.SerializeObject(
                new AccessScope()
                {
                    WildcardPath = "/custom_procedures/by_model/" + ModelId + "*",
                    AccessRights = new List<string>() { "GET" } //Only view access
                })));
                _Result.Add(JObject.Parse(JsonConvert.SerializeObject(
                new AccessScope()
                {
                    WildcardPath = "/3d/models/" + ModelId + "/remove_sharing_from/user_id/" + _UserID,
                    AccessRights = new List<string>() { "DELETE" }
                })));
            }

            return true;
        }
        public bool PerformGetRequestToGetGloballySharedModelIds(out List<string> _Result, Action<string> _ErrorMessageAction)
        {
            _Result = new List<string>();

            //Get cad file service endpoint from internal set state
            if (!InternalSetState.GetValueFromMemoryService(
                out string CADFileServiceEndpoint,
                InternalSetState.CAD_FILE_SERVICE_ENDPOINT_PROPERTY,
                MemoryService,
                (string _Message) =>
                {
                    _ErrorMessageAction?.Invoke("PerformGetRequestToGetGloballySharedModelIds: " + _Message);
                }))
            {
                return false;
            }

            var ListGloballySharedModelIdsEndpoint = CADFileServiceEndpoint + "/3d/models/internal/globally_shared_models?secret=" + CommonData.INTERNAL_CALL_PRIVATE_KEY;

            var Result = BWebUtilities_GC_CloudRun.InterServicesRequest(new BWebUtilities_GC_CloudRun.InterServicesRequestRequest()
            {
                DestinationServiceUrl = ListGloballySharedModelIdsEndpoint,
                RequestMethod = "GET",
                bWithAuthToken = true
                //UseContext not needed since it's a call to an internal endpoint
            },
            false,
            _ErrorMessageAction);

            string ResponseContentAsString = "";
            JObject ResponseContentAsJson = null;
            try
            {
                ResponseContentAsString = Result.Content.String;
                ResponseContentAsJson = JObject.Parse(ResponseContentAsString);

                var ArrayTmp = (JArray)ResponseContentAsJson["sharedModelIds"];
                foreach (var Tmp in ArrayTmp)
                {
                    _Result.Add((string)Tmp);
                }
            }
            catch (Exception e)
            {
                _ErrorMessageAction?.Invoke("PerformGetRequestToGetGloballySharedModelIds: Error occured during reading response/parsing json: " + e.Message + ", trace: " + e.StackTrace + ", response content: " + ResponseContentAsString + ", response code: " + Result.ResponseCode);
                return false;
            }
            if (Result.ResponseCode >= 400)
            {
                _ErrorMessageAction?.Invoke("PerformGetRequestToGetGloballySharedModelIds: Request did not end up with success. Response content: " + ResponseContentAsString + ", response code: " + Result.ResponseCode);
                return false;
            }
            return true;
        }

        public enum EChangeUserRightsForModelType
        {
            Add,
            Delete
        }
        public bool ChangeBaseUserRight(out bool _bInternalErrorOccured, bool _bDoNotGetDBClearance, EChangeUserRightsForModelType _Type, string _UserID, string _PathRegex, Action<string> _ErrorMessageAction, List<string> _Rights = null)
        {
            _bInternalErrorOccured = false;

            Task<HttpResponseMessage> RequestTask = null;
            StringContent RequestContent = null;

            using var Handler = new HttpClientHandler
            {
                SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls11 | SslProtocols.Tls,
                ServerCertificateCustomValidationCallback = (a, b, c, d) => true
            };
            using var Client = new HttpClient(Handler);
            Client.DefaultRequestHeaders.TryAddWithoutValidation("internal-call-secret", CommonData.INTERNAL_CALL_PRIVATE_KEY);
            Client.DefaultRequestHeaders.TryAddWithoutValidation("do-not-get-db-clearance", _bDoNotGetDBClearance ? "true" : "false");
            try
            {
                if (_Type == EChangeUserRightsForModelType.Add)
                {
                    RequestContent = new StringContent(
                        new JArray()
                        {
                                JObject.Parse(JsonConvert.SerializeObject(
                                    new AccessScope()
                                    {
                                        WildcardPath = _PathRegex,
                                        AccessRights = _Rights
                                    }))

                        }.ToString(), Encoding.UTF8, "application/json");

                    RequestTask = Client.PutAsync("http://localhost:" + LocalServerPort + "/auth/users/" + _UserID + "/base_access_rights", RequestContent);
                }
                else
                {
                    RequestTask = Client.DeleteAsync("http://localhost:" + LocalServerPort + "/auth/users/" + _UserID + "/base_access_rights/" + WebUtility.UrlEncode(_PathRegex));
                }

                RequestTask.Wait();

                using var Response = RequestTask.Result;
                using var ResponseContent = Response.Content;

                using var ReadResponseTask = ResponseContent.ReadAsStringAsync();
                ReadResponseTask.Wait();

                var ResponseString = ReadResponseTask.Result;

                if (!Response.IsSuccessStatusCode)
                {
                    _bInternalErrorOccured = (int)Response.StatusCode == BWebResponse.Error_InternalError_Code;
                    _ErrorMessageAction?.Invoke("Error: Controller_Rights_Internal->ChangeBaseUserRight: Request returned error. Code: " + Response.StatusCode + ", message: " + ResponseString);
                    return false;
                }
            }
            catch (Exception e)
            {
                if (e.InnerException != null && e.InnerException != e)
                {
                    _ErrorMessageAction?.Invoke("Error: Controller_Rights_Internal->ChangeBaseUserRight->Inner: " + e.InnerException.Message + ", Trace: " + e.InnerException.StackTrace);
                }
                if (e is AggregateException)
                {
                    foreach (var Inner in (e as AggregateException).InnerExceptions)
                    {
                        _ErrorMessageAction?.Invoke("Error: Controller_Rights_Internal->ChangeBaseUserRight->Aggregate->Inner: " + Inner.Message + ", Trace: " + Inner.StackTrace);
                    }
                }
                _bInternalErrorOccured = true;
                _ErrorMessageAction?.Invoke("Error: Controller_Rights_Internal->ChangeBaseUserRight: Request failed. Message: " + e.Message + ", trace: " + e.StackTrace);
                return false;
            }
            finally
            {
                try { RequestContent?.Dispose(); } catch (Exception) { }
                try { RequestTask?.Dispose(); } catch (Exception) { }
            }
            return true;
        }

        public bool GrantUserWithRights(bool _bDoNotGetDBClearance, string _UserID, JArray _Rights, Action<string> _ErrorMessageAction)
        {
            var Endpoint = "http://localhost:" + LocalServerPort + "/auth/users/" + _UserID + "/base_access_rights";

            using var Handler = new HttpClientHandler
            {
                SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls11 | SslProtocols.Tls,
                ServerCertificateCustomValidationCallback = (a, b, c, d) => true
            };
            using var Client = new HttpClient(Handler);
            Client.DefaultRequestHeaders.TryAddWithoutValidation("internal-call-secret", CommonData.INTERNAL_CALL_PRIVATE_KEY);
            Client.DefaultRequestHeaders.TryAddWithoutValidation("do-not-get-db-clearance", _bDoNotGetDBClearance ? "true" : "false");
            try
            {
                using var RequestContent = new StringContent(_Rights.ToString(), Encoding.UTF8, "application/json");

                using var RequestTask = Client.PutAsync(Endpoint, RequestContent);
                RequestTask.Wait();

                using var Response = RequestTask.Result;
                using var ResponseContent = Response.Content;

                using var ReadResponseTask = ResponseContent.ReadAsStringAsync();
                ReadResponseTask.Wait();

                var ResponseString = ReadResponseTask.Result;

                if (!Response.IsSuccessStatusCode)
                {
                    _ErrorMessageAction?.Invoke("Error: Controller_Rights_Internal->GrantUserWithRights: Request returned error. Endpoint: " + Endpoint + ", code: " + Response.StatusCode + ", message: " + ResponseString);
                    return false;
                }
            }
            catch (Exception e)
            {
                if (e.InnerException != null && e.InnerException != e)
                {
                    _ErrorMessageAction?.Invoke("Error: Controller_Rights_Internal->GrantUserWithRights->Inner: " + e.InnerException.Message + ", Trace: " + e.InnerException.StackTrace);
                }
                if (e is AggregateException)
                {
                    foreach (var Inner in (e as AggregateException).InnerExceptions)
                    {
                        _ErrorMessageAction?.Invoke("Error: Controller_Rights_Internal->GrantUserWithRights->Aggregate->Inner: " + Inner.Message + ", Trace: " + Inner.StackTrace);
                    }
                }
                _ErrorMessageAction?.Invoke("Error: Controller_Rights_Internal->GrantUserWithRights: Request failed. Endpoint: " + Endpoint + ", message: " + e.Message + ", trace: " + e.StackTrace);
                return false;
            }
            return true;
        }
    }
}