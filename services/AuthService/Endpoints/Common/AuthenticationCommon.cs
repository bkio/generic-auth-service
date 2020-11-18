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
        public static bool FetchUserInfoFromMemoryService_ByMethod(
            IBMemoryServiceInterface _MemoryService,
            string _Method,
            out string _UserID,
            out string _UserEmail,
            out string _UserName,
            Action<string> _ErrorMessageAction = null)
        {
            _UserID = null;
            _UserEmail = null;
            _UserName = null;

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

                    return true;
                }
                catch (Exception) { }
            }
            return false;
        }

        public static bool FetchUserInfoFromDatabaseService_ByMethod(
            IBDatabaseServiceInterface _DatabaseService,
            IBMemoryServiceInterface _MemoryService,
            string _Method,
            out string _UserID,
            out string _UserEmail,
            out string _UserName,
            out BWebServiceResponse _FailureResponse,
            Action<string> _ErrorMessageAction = null)
        {
            _UserID = null;
            _UserEmail = null;
            _UserName = null;
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

        public static bool FetchBaseAccessRights_ByMethod(
            IBDatabaseServiceInterface _DatabaseService,
            IBMemoryServiceInterface _MemoryService,
            string _Method,
            out List<AccessScope> _AccessScopes,
            out string _UserID,
            out string _UserEmail,
            out string _UserName,
            out BWebServiceResponse _FailureResponse,
            Action<string> _ErrorMessageAction = null)
        {
            _AccessScopes = null;

            if (!FetchUserInfoFromMemoryService_ByMethod(_MemoryService, _Method, out _UserID, out _UserEmail, out _UserName, _ErrorMessageAction))
            {
                if (!FetchUserInfoFromDatabaseService_ByMethod(_DatabaseService, _MemoryService, _Method, out _UserID, out _UserEmail, out _UserName, out _FailureResponse, _ErrorMessageAction))
                {
                    return false;
                }
            }

            return FetchBaseAccessRights_ByUserID(_DatabaseService, _MemoryService, _UserID, out _AccessScopes, out _FailureResponse, _ErrorMessageAction);
        }

        public static bool FetchBaseAccessRights_ByUserID(
            IBDatabaseServiceInterface _DatabaseService,
            IBMemoryServiceInterface _MemoryService,
            string _UserID,
            out List<AccessScope> _AccessScopes,
            out BWebServiceResponse _FailureResponse,
            Action<string> _ErrorMessageAction = null)
        {
            _AccessScopes = null;
            _FailureResponse = new BWebServiceResponse();

            var InMemoryResult = _MemoryService.GetKeyValue(CommonData.MemoryQueryParameters, UserBaseAccessMEntry.M_KEY_NAME_USER_ID + _UserID, _ErrorMessageAction);
            if (InMemoryResult != null)
            {
                try
                {
                    _AccessScopes = JsonConvert.DeserializeObject<UserBaseAccessMEntry>(InMemoryResult.AsString).BaseAccessScope;
                    return true;
                }
                catch (Exception) { }
            }

            if (!_DatabaseService.GetItem(
                UserDBEntry.DBSERVICE_USERS_TABLE(),
                UserDBEntry.KEY_NAME_USER_ID,
                new BPrimitiveType(_UserID),
                UserDBEntry.Properties,
                out JObject UserObject,
                _ErrorMessageAction))
            {
                _FailureResponse = BWebResponse.InternalError("Database fetch-user-info operation has failed.");
                return false;
            }
            if (UserObject == null)
            {
                _FailureResponse = BWebResponse.NotFound("User does not exist.");
                return false;
            }

            _AccessScopes = new List<AccessScope>();

            if (UserObject.ContainsKey(UserDBEntry.BASE_ACCESS_SCOPE_PROPERTY))
            {
                var BaseAccessScopeAsArray = (JArray)UserObject[UserDBEntry.BASE_ACCESS_SCOPE_PROPERTY];

                foreach (JObject ScopeObject in BaseAccessScopeAsArray)
                {
                    _AccessScopes.Add(JsonConvert.DeserializeObject<AccessScope>(ScopeObject.ToString()));
                }
            }

            _MemoryService.SetKeyValue(CommonData.MemoryQueryParameters, new Tuple<string, BPrimitiveType>[]
                {
                    new Tuple<string, BPrimitiveType>(
                        UserBaseAccessMEntry.M_KEY_NAME_USER_ID + _UserID,
                        new BPrimitiveType(JsonConvert.SerializeObject(new UserBaseAccessMEntry()
                        {
                            BaseAccessScope = _AccessScopes
                        })))
                }, _ErrorMessageAction);

            return true;
        }
    }
}