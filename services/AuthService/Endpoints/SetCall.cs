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
                string ApiPassthroughPublicEndpoint = null;
                string CADFileServiceEndpoint = null;

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

                if (!ParsedBody.ContainsKey(InternalSetState.API_PASSTHROUGH_PUBLIC_ENDPOINT_PROPERTY) 
                    && !ParsedBody.ContainsKey(InternalSetState.CAD_FILE_SERVICE_ENDPOINT_PROPERTY))
                {
                    _ErrorMessageAction?.Invoke("SetCallRequest-> Request does not have required fields.");
                    return BWebResponse.BadRequest("Request does not have required fields.");
                }

                var LocalErrorMessage = "";

                if (ParsedBody.ContainsKey(InternalSetState.API_PASSTHROUGH_PUBLIC_ENDPOINT_PROPERTY))
                {
                    ApiPassthroughPublicEndpoint = (string)ParsedBody[InternalSetState.API_PASSTHROUGH_PUBLIC_ENDPOINT_PROPERTY];
                    if (!Process_SetApiPassthroughPublicEndpoint((string _Message) => { LocalErrorMessage = _Message; }, ApiPassthroughPublicEndpoint))
                    {
                        return BWebResponse.InternalError(LocalErrorMessage);
                    }
                }
                if (ParsedBody.ContainsKey(InternalSetState.CAD_FILE_SERVICE_ENDPOINT_PROPERTY))
                {
                    CADFileServiceEndpoint = (string)ParsedBody[InternalSetState.CAD_FILE_SERVICE_ENDPOINT_PROPERTY];
                    if (!Process_SetCADFileServicePublicEndpoint((string _Message) => { LocalErrorMessage = _Message; }, CADFileServiceEndpoint))
                    {
                        return BWebResponse.InternalError(LocalErrorMessage);
                    }
                }

                return BWebResponse.StatusOK("Ok.");
            }

            public bool Process_SetApiPassthroughPublicEndpoint(Action<string> _ErrorMessageAction, string _ApiPassthroughPublicEndpoint)
            {
                return InternalSetState.SetValueToMemoryService(
                       InternalSetState.API_PASSTHROUGH_PUBLIC_ENDPOINT_PROPERTY,
                       _ApiPassthroughPublicEndpoint,
                       MemoryService,
                       _ErrorMessageAction);
            }

            public bool Process_SetCADFileServicePublicEndpoint(Action<string> _ErrorMessageAction, string _CADFileServiceEndpoint)
            {
                return InternalSetState.SetValueToMemoryService(
                       InternalSetState.CAD_FILE_SERVICE_ENDPOINT_PROPERTY,
                       _CADFileServiceEndpoint,
                       MemoryService,
                       _ErrorMessageAction);
            }
        }
    }
}