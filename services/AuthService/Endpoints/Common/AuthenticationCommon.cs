/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System;
using System.Collections.Generic;
using AuthService.Endpoints.Structures;
using BCloudServiceUtilities;
using BCommonUtilities;
using BWebServiceUtilities;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AuthService.Endpoints.Common
{
    public class AuthenticationCommon
    {
        public static bool FetchFromMemoryService(
            IBMemoryServiceInterface _MemoryService,
            string _Method,
            out string _UserID,
            out string _UserEmail,
            out string _UserName,
            out List<AccessScope> _ScopeAccess,
            Action<string> _ErrorMessageAction = null)
        {
            _UserID = null;
            _UserEmail = null;
            _UserName = null;
            _ScopeAccess = null;

            var InMemoryResult = _MemoryService.GetKeyValue(CommonData.MemoryQueryParameters, AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY + _Method, _ErrorMessageAction);
            if (InMemoryResult != null)
            {
                try
                {
                    var AuthEntry = JsonConvert.DeserializeObject<AuthDBEntry>(InMemoryResult.AsString);
                    
                    _UserID = AuthEntry.UserID;
                    _UserEmail = AuthEntry.UserEmail;
                    _UserName = AuthEntry.UserName;

                    if (_UserID == null || _UserID.Length == 0
                        || _UserEmail == null || _UserEmail.Length == 0
                        || _UserName == null || _UserName.Length == 0)
                    {
                        _ErrorMessageAction?.Invoke("Method " + _Method + " exists in the memoryservice; but fields are null or empty. Deleting the entry.");
                        _MemoryService.DeleteKey(CommonData.MemoryQueryParameters, AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY + _Method, _ErrorMessageAction);
                        return false;
                    }

                    _ScopeAccess = AuthEntry.FinalAccessScope;
                    return true;
                }
                catch (Exception) { }
            }
            return false;
        }

        public static bool FetchFromDatabaseService(
            IBDatabaseServiceInterface _DatabaseService,
            IBMemoryServiceInterface _MemoryService,
            string _Method,
            out string _UserID,
            out string _UserEmail,
            out string _UserName,
            out List<AccessScope> _ScopeAccess,
            out BWebServiceResponse _FailureResponse,
            Action<string> _ErrorMessageAction = null)
        {
            _UserID = null;
            _UserEmail = null;
            _UserName = null;
            _ScopeAccess = null;
            _FailureResponse = new BWebServiceResponse();

            string ReturnedEntryAsString = null;

            if (!_DatabaseService.GetItem(
                    AuthDBEntry.DBSERVICE_AUTHMETHODS_TABLE(),
                    AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY,
                    new BPrimitiveType(_Method),
                    AuthDBEntry.Properties,
                    out JObject ReturnedObject,
                    _ErrorMessageAction))
            {
                _FailureResponse = BWebResponse.InternalError("Database fetch operation has failed");
                return false;
            }
            if (ReturnedObject == null)
            {
                _ErrorMessageAction?.Invoke("FetchFromDatabaseService: Given credentials are invalid: " + _Method);
                _FailureResponse = BWebResponse.Unauthorized("Given credentials are invalid.");
                return false;
            }

            try
            {
                ReturnedEntryAsString = ReturnedObject.ToString();
                var ReturnedEntry = JsonConvert.DeserializeObject<AuthDBEntry>(ReturnedEntryAsString);
                _UserID = ReturnedEntry.UserID;
                _UserEmail = ReturnedEntry.UserEmail;
                _UserName = ReturnedEntry.UserName;
                _ScopeAccess = ReturnedEntry.FinalAccessScope;
            }
            catch (Exception e)
            {
                _ErrorMessageAction?.Invoke("FetchFromDatabaseService: " + e.Message + ", Trace: " + e.StackTrace);
                _FailureResponse = BWebResponse.InternalError("Database fetch operation failed.");
                return false;
            }

            _MemoryService.SetKeyValue(CommonData.MemoryQueryParameters, new Tuple<string, BPrimitiveType>[]
            {
                new Tuple<string, BPrimitiveType>(AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY + _Method, new BPrimitiveType(ReturnedEntryAsString))
            },
            _ErrorMessageAction);

            return true;
        }
    }
}