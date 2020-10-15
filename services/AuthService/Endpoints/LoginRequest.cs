/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using AuthService.Endpoints.Common;
using AuthService.Endpoints.Structures;
using BCloudServiceUtilities;
using BCommonUtilities;
using BWebServiceUtilities;
using ServiceUtilities;
using ServiceUtilities.All;
using Newtonsoft.Json.Linq;

namespace AuthService.Endpoints
{
    internal class LoginRequest : BppWebServiceBase
    {
        private readonly IBDatabaseServiceInterface DatabaseService;
        private readonly IBMemoryServiceInterface MemoryService;

        public LoginRequest(IBDatabaseServiceInterface _DatabaseService, IBMemoryServiceInterface _MemoryService)
        {
            DatabaseService = _DatabaseService;
            MemoryService = _MemoryService;
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
            if (_Context.Request.HttpMethod != "POST")
            {
                _ErrorMessageAction?.Invoke("LoginRequest: POST method is accepted. But received request method:  " + _Context.Request.HttpMethod);
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
                        _ErrorMessageAction?.Invoke("LoginRequest-> Read request body stage has failed. Exception: " + e.Message + ", Trace: " + e.StackTrace);
                        return BWebResponse.BadRequest("Malformed request body. Request must be a valid json form.");
                    }
                }
            }

            if (!ParsedBody.ContainsKey(AuthMethod.API_KEY_PROPERTY) &&
                ((!ParsedBody.ContainsKey(AuthMethod.USER_NAME_PROPERTY) && !ParsedBody.ContainsKey(AuthMethod.USER_EMAIL_PROPERTY)) || !ParsedBody.ContainsKey(AuthMethod.PASSWORD_MD5_PROPERTY)))
            {
                _ErrorMessageAction?.Invoke("LoginRequest-> Request does not have required fields.");
                return BWebResponse.BadRequest("Request does not have required fields.");
            }

            string Method;

            if (ParsedBody.ContainsKey(AuthMethod.API_KEY_PROPERTY))
            {
                var ApiKey = (string)ParsedBody[AuthMethod.API_KEY_PROPERTY];
                Method = ApiKey;
            }
            else
            {
                var PasswordMD5 = ((string)ParsedBody[AuthMethod.PASSWORD_MD5_PROPERTY]).ToLower();

                if (ParsedBody.ContainsKey(UserDBEntry.USER_NAME_PROPERTY))
                {
                    Method = (string)ParsedBody[UserDBEntry.USER_NAME_PROPERTY] + PasswordMD5;
                }
                else
                {
                    Method = ((string)ParsedBody[UserDBEntry.USER_EMAIL_PROPERTY]).ToLower() + PasswordMD5;
                }
            }

            if (!AuthenticationCommon.FetchFromMemoryService(MemoryService, Method, out string UserID, out string _, out string _, out List<AccessScope> _, _ErrorMessageAction))
            {
                if (!AuthenticationCommon.FetchFromDatabaseService(DatabaseService, MemoryService, Method, out UserID, out _, out _, out List<AccessScope> _, out BWebServiceResponse FailureResponse, _ErrorMessageAction))
                {
                    return FailureResponse;
                }
            }

            if (!BUtility.CalculateStringMD5(BUtility.RandomString(32, true), out string AccessTokenMD5, _ErrorMessageAction))
            {
                return BWebResponse.InternalError("Hash operation failed.");
            }

            var AccessTokenMD5WithTokenType = "Security " + AccessTokenMD5;

            var QueryParameters = new BMemoryQueryParameters()
            {
                Domain = Resources_DeploymentManager.Get().GetDeploymentBranchNameEscapedLoweredWithDash().ToUpper(),
                SubDomain = "SELF_SIGNED_ACCESS_TOKEN_VALIDATION",
                Identifier = AccessTokenMD5WithTokenType
            };

            MemoryService.SetKeyValue(QueryParameters, new Tuple<string, BPrimitiveType>[]
            {
                new Tuple<string, BPrimitiveType>("method", new BPrimitiveType(Method))
            }, 
            _ErrorMessageAction);

            MemoryService.SetKeyExpireTime(QueryParameters, TimeSpan.FromHours(1), _ErrorMessageAction);

            return BWebResponse.StatusOK("Login successful.", new JObject()
            {
                ["userId"] = UserID,
                ["token"] = AccessTokenMD5WithTokenType

            });
        }
    }
}