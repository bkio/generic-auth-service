/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System;
using System.Collections.Generic;
using System.Net;
using AuthService.Endpoints.Structures;
using BCloudServiceUtilities;
using BWebServiceUtilities;
using ServiceUtilities.All;
using Newtonsoft.Json.Linq;

namespace AuthService.Endpoints
{
    internal class ListRegisteredUserEmails : BppWebServiceBase
    {
        private readonly IBDatabaseServiceInterface DatabaseService;

        public ListRegisteredUserEmails(IBDatabaseServiceInterface _DatabaseService)
        {
            DatabaseService = _DatabaseService;
        }

        protected override BWebServiceResponse OnRequestPP(HttpListenerContext _Context, Action<string> _ErrorMessageAction = null)
        {
            if (_Context.Request.HttpMethod != "GET")
            {
                _ErrorMessageAction?.Invoke("ListRegisteredUserEmails: GET method is accepted. But received request method:  " + _Context.Request.HttpMethod);
                return BWebResponse.MethodNotAllowed("GET method is accepted. But received request method: " + _Context.Request.HttpMethod);
            }

            if (!DatabaseService.ScanTable(UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(), out List<JObject> Result, _ErrorMessageAction))
            {
                return BWebResponse.InternalError("ScanTable has failed.");
            }
            if (Result == null) return BWebResponse.StatusOK("Ok.", new JObject() { ["emailAddresses"] = new JArray() });

            var FinalResultArray = new JArray();

            foreach (var Current in Result)
            {
                if (Current != null 
                    && Current.ContainsKey(UniqueUserFieldsDBEntry.KEY_NAME_USER_EMAIL)
                    && Current.ContainsKey(UserDBEntry.KEY_NAME_USER_ID))
                {
                    FinalResultArray.Add(
                        new JObject()
                        {
                            [UniqueUserFieldsDBEntry.KEY_NAME_USER_EMAIL] = (string)Current[UniqueUserFieldsDBEntry.KEY_NAME_USER_EMAIL],
                            [UserDBEntry.KEY_NAME_USER_ID] = (string)Current[UserDBEntry.KEY_NAME_USER_ID]
                        });
                }
            }
            return BWebResponse.StatusOK("Ok.", new JObject() { ["emailAddresses"] = FinalResultArray });
        }
    }
}