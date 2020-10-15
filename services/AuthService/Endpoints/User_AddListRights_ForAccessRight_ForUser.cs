/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using AuthService.Endpoints.Common;
using AuthService.Endpoints.Structures;
using BCloudServiceUtilities;
using BCommonUtilities;
using BWebServiceUtilities;
using ServiceUtilities;
using ServiceUtilities.PubSubUsers.PubSubRelated;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AuthService
{
    internal class User_AddListRights_ForAccessRight_ForUser : WebServiceBaseTimeoutableDeliveryEnsurerUser
    {
        private readonly IBDatabaseServiceInterface DatabaseService;
        private readonly IBMemoryServiceInterface MemoryService;
        private readonly string RestfulUrlParameter_UsersKey;
        private readonly string RestfulUrlParameter_AccessMethodKey;

        private string RequestedUserID;
        private string RequestedAuthMethodKey;

        public User_AddListRights_ForAccessRight_ForUser(IBDatabaseServiceInterface _DatabaseService, IBMemoryServiceInterface _MemoryService, string _RestfulUrlParameter_UsersKey, string _RestfulUrlParameter_AccessMethodKey)
        {
            DatabaseService = _DatabaseService;
            MemoryService = _MemoryService;
            RestfulUrlParameter_UsersKey = _RestfulUrlParameter_UsersKey;
            RestfulUrlParameter_AccessMethodKey = _RestfulUrlParameter_AccessMethodKey;
        }

        public override BWebServiceResponse OnRequest_Interruptable_DeliveryEnsurerUser(HttpListenerContext _Context, Action<string> _ErrorMessageAction = null)
        {
            GetTracingService()?.On_FromGatewayToService_Received(_Context, _ErrorMessageAction);

            var Result = OnRequest_Internal(_Context, _ErrorMessageAction);

            GetTracingService()?.On_FromServiceToGateway_Sent(_Context, _ErrorMessageAction);

            return Result;
        }

        private BWebServiceResponse OnRequest_Internal(HttpListenerContext _Context, Action<string> _ErrorMessageAction = null)
        {
            if (_Context.Request.HttpMethod != "GET" && _Context.Request.HttpMethod != "PUT")
            {
                _ErrorMessageAction?.Invoke("User_AddListRights_ForAccessRight_ForUser: GET and PUT methods are accepted. But received request method:  " + _Context.Request.HttpMethod);
                return BWebResponse.MethodNotAllowed("GET and PUT methods are accepted. But received request method: " + _Context.Request.HttpMethod);
            }

            RequestedUserID = RestfulUrlParameters[RestfulUrlParameter_UsersKey];
            RequestedAuthMethodKey = WebUtility.UrlDecode(RestfulUrlParameters[RestfulUrlParameter_AccessMethodKey]);

            if (_Context.Request.HttpMethod == "GET")
            {
                return GetFinalRightsForUserForAccessMethod(_ErrorMessageAction);
            }

            if (!Controller_AtomicDBOperation.Get().GetClearanceForDBOperation(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), RequestedUserID, _ErrorMessageAction))
            {
                return BWebResponse.InternalError("Atomic operation control has failed.");
            }
                
            var Result = AddFinalRightsForUserForAccessMethod(_Context, _ErrorMessageAction);
                
            Controller_AtomicDBOperation.Get().SetClearanceForDBOperationForOthers(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), RequestedUserID, _ErrorMessageAction);
                
            return Result;
        }

        private BWebServiceResponse GetFinalRightsForUserForAccessMethod(Action<string> _ErrorMessageAction)
        {
            var UserKey = new BPrimitiveType(RequestedUserID);
            var AuthDBEntryKey = new BPrimitiveType(RequestedAuthMethodKey);

            if (!DatabaseService.GetItem(
                AuthDBEntry.DBSERVICE_AUTHMETHODS_TABLE(),
                AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY,
                AuthDBEntryKey,
                new string[]
                {
                    AuthDBEntry.FINAL_ACCESS_SCOPE_PROPERTY
                },
                out JObject AuthDBEntryObject_OnlyWithFinalAccessScope,
                _ErrorMessageAction))
            {
                return BWebResponse.InternalError("Database fetch-auth-method-info operation has failed.");
            }
            if (AuthDBEntryObject_OnlyWithFinalAccessScope == null)
            {
                return BWebResponse.NotFound($"Given auth method does not exist. UserKey - [{UserKey}], AuthDBEntryKey - [{AuthDBEntryKey}]");
            }
            if (!AuthDBEntryObject_OnlyWithFinalAccessScope.ContainsKey(AuthDBEntry.FINAL_ACCESS_SCOPE_PROPERTY))
            {
                return BWebResponse.NotFound("Given auth method does not contain any access scope.");
            }

            return BWebResponse.StatusOK("List final rights operation has succeeded.", AuthDBEntryObject_OnlyWithFinalAccessScope);
        }

        private BWebServiceResponse AddFinalRightsForUserForAccessMethod(HttpListenerContext _Context, Action<string> _ErrorMessageAction)
        {
            var NewFinalScopeList = new List<AccessScope>();

            using (var InputStream = _Context.Request.InputStream)
            {
                using (var ResponseReader = new StreamReader(InputStream))
                {
                    try
                    {
                        var NewScopes = JArray.Parse(ResponseReader.ReadToEnd());
                        foreach (JObject NewScope in NewScopes)
                        {
                            var ConvertedScope = JsonConvert.DeserializeObject<AccessScope>(NewScope.ToString());
                            for (int i = ConvertedScope.AccessRights.Count - 1; i >= 0; i--)
                            {
                                ConvertedScope.AccessRights[i] = ConvertedScope.AccessRights[i].ToUpper();
                                if (!AccessScopeLibrary.ACCESS_RIGHTS.Contains(ConvertedScope.AccessRights[i]))
                                {
                                    ConvertedScope.AccessRights.RemoveAt(i);
                                }
                            }

                            if (ConvertedScope.AccessRights.Count > 0)
                            {
                                ConvertedScope.AccessRights = ConvertedScope.AccessRights.Distinct().ToList();
                                NewFinalScopeList.Add(ConvertedScope);
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        _ErrorMessageAction?.Invoke("User_AddListRights_ForAccessRight_ForUser->AddFinalRightsForUserForAccessMethod: Read request body stage has failed. Exception: " + e.Message + ", Trace: " + e.StackTrace);
                        return BWebResponse.BadRequest("Malformed request body. Request must be a valid json form.");
                    }
                }
            }
            
            if (NewFinalScopeList.Count == 0)
            {
                return BWebResponse.BadRequest("Request does not contain any valid final scope. Access rights can be: " + AccessScopeLibrary.GetPossibleAccessRightsText());
            }

            var UserKey = new BPrimitiveType(RequestedUserID);
            var AuthDBEntryKey = new BPrimitiveType(RequestedAuthMethodKey);
            
            if (!DatabaseService.GetItem(
                UserDBEntry.DBSERVICE_USERS_TABLE(),
                UserDBEntry.KEY_NAME_USER_ID,
                UserKey,
                UserDBEntry.Properties,
                out JObject UserObject,
                _ErrorMessageAction))
            {
                return BWebResponse.InternalError("Database fetch operation has failed.");
            }
            if (!UserObject.ContainsKey(UserDBEntry.BASE_ACCESS_SCOPE_PROPERTY))
            {
                return BWebResponse.Forbidden("User does not have any base rights.");
            }

            var BaseScopeList = new List<AccessScope>();
            var BaseScopesArray = (JArray)UserObject[UserDBEntry.BASE_ACCESS_SCOPE_PROPERTY];
            foreach (JObject BaseScopeObject in BaseScopesArray)
            {
                BaseScopeList.Add(JsonConvert.DeserializeObject<AccessScope>(BaseScopeObject.ToString()));
            }

            if (!AccessScopeLibrary.CheckBaseFinalFullContainment(BaseScopeList, NewFinalScopeList))
            {
                return BWebResponse.Forbidden("User does not have requested rights in user's base rights.");
            }

            if (!UserObject.ContainsKey(UserDBEntry.AUTH_METHODS_PROPERTY))
            {
                return BWebResponse.NotFound("User does not have any auth method.");
            }

            if (!DatabaseService.GetItem(
                AuthDBEntry.DBSERVICE_AUTHMETHODS_TABLE(),
                AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY,
                AuthDBEntryKey,
                AuthDBEntry.Properties,
                out JObject AuthDBEntryObject,
            _ErrorMessageAction))
            {
                return BWebResponse.InternalError("Database fetch-auth-method-info operation has failed.");
            }
            if (AuthDBEntryObject == null)
            {
                return BWebResponse.NotFound("Given auth method does not exist.");
            }
            var AuthEntry = JsonConvert.DeserializeObject<AuthDBEntry>(AuthDBEntryObject.ToString());

            AccessScopeLibrary.CombineRightsOfAccessScopeLists_IntoNew(NewFinalScopeList, AuthEntry.FinalAccessScope);

            AuthEntry.FinalAccessScope = NewFinalScopeList;

            var AuthEntryAsJsonString = JsonConvert.SerializeObject(AuthEntry);
            var AuthEntryAsJsonObject = JObject.Parse(AuthEntryAsJsonString);

            Controller_DeliveryEnsurer.Get().DB_UpdateItem_FireAndForget(
                _Context,
                AuthDBEntry.DBSERVICE_AUTHMETHODS_TABLE(),
                AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY,
                AuthDBEntryKey,
                AuthEntryAsJsonObject);

            MemoryService.SetKeyValue(CommonData.MemoryQueryParameters,
                new Tuple<string, BPrimitiveType>[]
                {
                    new Tuple<string, BPrimitiveType>(AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY + AuthDBEntryKey.AsString, new BPrimitiveType(AuthEntryAsJsonString))
                },
                _ErrorMessageAction);

            return BWebResponse.StatusCreated("Final rights for the access method has been added.");
        }
    }
}