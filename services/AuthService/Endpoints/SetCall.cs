/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System;
using System.Net;
using System.IO;
using BCloudServiceUtilities;
using BWebServiceUtilities;
using Newtonsoft.Json.Linq;
using ServiceUtilities.All;
using AuthService.Endpoints.Structures;

namespace AuthService.Endpoints
{
    partial class InternalCalls
    {
        internal class SetCall : InternalWebServiceBase
        {
            private readonly IBMemoryServiceInterface MemoryService;

            public SetCall(string _InternalCallPrivateKey, IBMemoryServiceInterface _MemoryService) : base(_InternalCallPrivateKey)
            {
                MemoryService = _MemoryService;
            }

            protected override BWebServiceResponse Process(HttpListenerContext _Context, Action<string> _ErrorMessageAction = null)
            {
                string ApiGatewayPublicUrl = null;

                if (_Context.Request.HttpMethod != "POST")
                {
                    _ErrorMessageAction?.Invoke("SetCallRequest: POST method is accepted. But received request method:  " + _Context.Request.HttpMethod);
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
                            _ErrorMessageAction?.Invoke("SetCallRequest-> Read request body stage has failed. Exception: " + e.Message + ", Trace: " + e.StackTrace);
                            return BWebResponse.BadRequest("Malformed request body. Request must be a valid json form.");
                        }
                    }
                }

                if (!ParsedBody.ContainsKey(InternalSetState.API_GATEWAY_PUBLIC_URL_PROPERTY))
                {
                    _ErrorMessageAction?.Invoke("SetCallRequest-> Request does not have required fields.");
                    return BWebResponse.BadRequest("Request does not have required fields.");
                }

                var LocalErrorMessage = "";

                if (ParsedBody.ContainsKey(InternalSetState.API_GATEWAY_PUBLIC_URL_PROPERTY))
                {
                    ApiGatewayPublicUrl = (string)ParsedBody[InternalSetState.API_GATEWAY_PUBLIC_URL_PROPERTY];
                    if (!Process_SetApiGatewayPublicUrl(ApiGatewayPublicUrl, (string _Message) => { LocalErrorMessage = _Message; }))
                    {
                        return BWebResponse.InternalError(LocalErrorMessage);
                    }
                }

                return BWebResponse.StatusOK("Ok.");
            }

            public bool Process_SetApiGatewayPublicUrl(string _ApiGatewayPublicUrl, Action<string> _ErrorMessageAction)
            {
                return InternalSetState.SetValueToMemoryService(
                       InternalSetState.API_GATEWAY_PUBLIC_URL_PROPERTY,
                       _ApiGatewayPublicUrl,
                       MemoryService,
                       _ErrorMessageAction);
            }
        }
    }
}