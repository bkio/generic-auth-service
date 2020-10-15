/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using AuthService.Endpoints.Structures;
using BCloudServiceUtilities;
using BCommonUtilities;
using BWebServiceUtilities;
using ServiceUtilities.All;
using Newtonsoft.Json.Linq;

namespace AuthService.Endpoints
{
    partial class InternalCalls
    {
        internal class FetchUserIDsFromEmailsRequest : InternalWebServiceBase
        {
            private readonly IBDatabaseServiceInterface DatabaseService;

            public FetchUserIDsFromEmailsRequest(string _InternalCallPrivateKey, IBDatabaseServiceInterface _DatabaseService) : base(_InternalCallPrivateKey)
            {
                DatabaseService = _DatabaseService;
            }

            protected override BWebServiceResponse Process(HttpListenerContext _Context, Action<string> _ErrorMessageAction = null)
            {
                if (_Context.Request.HttpMethod != "POST")
                {
                    _ErrorMessageAction?.Invoke("GetUserIDsFromEmailsRequest: POST method is accepted. But received request method:  " + _Context.Request.HttpMethod);
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
                        _ErrorMessageAction?.Invoke("GetUserIDsFromEmailsRequest-> Malformed request body. Body content: " + RequestPayload + ", Exception: " + e.Message + ", Trace: " + e.StackTrace);
                        return BWebResponse.BadRequest("Malformed request body. Request must be a valid json form.");
                    }
                }

                if (!ParsedBody.ContainsKey("emailAddresses") || ParsedBody["emailAddresses"].Type != JTokenType.Array)
                {
                    return BWebResponse.BadRequest("Invalid request body.");
                }
                var AsJArray = (JArray)ParsedBody["emailAddresses"];

                var EmailAddresses = new List<string>();
                foreach (var Token in AsJArray)
                {
                    if (Token.Type != JTokenType.String)
                        return BWebResponse.BadRequest("Invalid request body.");

                    var EmailAddress = ((string)Token).ToLower();
                    if (!EmailAddresses.Contains(EmailAddress))
                    {
                        EmailAddresses.Add(EmailAddress);
                    }
                }

                if (EmailAddresses.Count == 0)
                    return BWebResponse.BadRequest("Empty emailAddresses field.");

                var ResponseObject = new JObject();

                foreach (var Email in EmailAddresses)
                {
                    if (!DatabaseService.GetItem(
                        UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(),
                        UniqueUserFieldsDBEntry.KEY_NAME_USER_EMAIL,
                        new BPrimitiveType(Email),
                        UniqueUserFieldsDBEntry.Properties,
                        out JObject ExistenceCheck,
                        _ErrorMessageAction))
                    {
                        return BWebResponse.InternalError("Database fetch-uniqueness-info operation has failed.");
                    }
                    if (ExistenceCheck == null)
                    {
                        return BWebResponse.NotFound("A user with e-mail " + Email + " does not exist.");
                    }

                    ResponseObject[Email] = (string)ExistenceCheck[UserDBEntry.KEY_NAME_USER_ID];
                }

                return BWebResponse.StatusOK("OK.", new JObject()
                {
                    ["map"] = ResponseObject
                });
            }
        }
    }
}