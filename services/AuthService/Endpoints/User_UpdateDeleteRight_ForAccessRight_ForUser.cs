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
    internal class User_UpdateDeleteRight_ForAccessRight_ForUser : WebServiceBaseTimeoutableDeliveryEnsurerUser
    {
        private readonly IBDatabaseServiceInterface DatabaseService;
        private readonly IBMemoryServiceInterface MemoryService;
        private readonly string RestfulUrlParameter_UsersKey;
        private readonly string RestfulUrlParameter_AccessMethodKey;
        private readonly string RestfulUrlParameter_FinalAccessRightsKey;

        private string RequestedUserID;
        private string RequestedAuthMethodKey;
        private string RequestedFinalRightWildcard;

        public User_UpdateDeleteRight_ForAccessRight_ForUser(IBDatabaseServiceInterface _DatabaseService, IBMemoryServiceInterface _MemoryService, string _RestfulUrlParameter_UsersKey, string _RestfulUrlParameter_AccessMethodKey, string _RestfulUrlParameter_FinalAccessRightsKey)
        {
            DatabaseService = _DatabaseService;
            MemoryService = _MemoryService;
            RestfulUrlParameter_UsersKey = _RestfulUrlParameter_UsersKey;
            RestfulUrlParameter_AccessMethodKey = _RestfulUrlParameter_AccessMethodKey;
            RestfulUrlParameter_FinalAccessRightsKey = _RestfulUrlParameter_FinalAccessRightsKey;
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
            if (_Context.Request.HttpMethod != "POST" && _Context.Request.HttpMethod != "DELETE")
            {
                _ErrorMessageAction?.Invoke("User_UpdateDeleteRight_ForAccessRight_ForUser: POST and DELETE methods are accepted. But received request method:  " + _Context.Request.HttpMethod);
                return BWebResponse.MethodNotAllowed("POST and DELETE methods are accepted. But received request method: " + _Context.Request.HttpMethod);
            }

            RequestedUserID = RestfulUrlParameters[RestfulUrlParameter_UsersKey];
            RequestedAuthMethodKey = WebUtility.UrlDecode(RestfulUrlParameters[RestfulUrlParameter_AccessMethodKey]);
            RequestedFinalRightWildcard = WebUtility.UrlDecode(RestfulUrlParameters[RestfulUrlParameter_FinalAccessRightsKey]);

            if (!Controller_AtomicDBOperation.Get().GetClearanceForDBOperation(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), RequestedUserID, _ErrorMessageAction))
            {
                return BWebResponse.InternalError("Atomic operation control has failed.");
            }

            BWebServiceResponse Result;
            if (_Context.Request.HttpMethod == "POST")
            {
                Result = UpdateFinalRightForUserForAccessMethod(_Context, _ErrorMessageAction);
            }
            else
            {
                Result = DeleteFinalRightForUserForAccessMethod(_Context, _ErrorMessageAction);
            }

            Controller_AtomicDBOperation.Get().SetClearanceForDBOperationForOthers(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), RequestedUserID, _ErrorMessageAction);

            return Result;
        }

        private bool GetAuthDBEntryObject(out JObject _AuthDBEntryObject, out BWebServiceResponse _ErrorResponse, Action<string> _ErrorMessageAction = null)
        {
            _ErrorResponse = BWebResponse.InternalError("");

            var AuthDBEntryKey = new BPrimitiveType(RequestedAuthMethodKey);

            if (!DatabaseService.GetItem(
                AuthDBEntry.DBSERVICE_AUTHMETHODS_TABLE(),
                AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY,
                AuthDBEntryKey,
                AuthDBEntry.Properties,
                out _AuthDBEntryObject,
            _ErrorMessageAction))
            {
                _ErrorResponse = BWebResponse.InternalError("Database fetch-auth-method-info operation has failed.");
                return false;
            }
            if (_AuthDBEntryObject == null)
            {
                _ErrorResponse = BWebResponse.NotFound("Given auth method does not exist.");
                return false;
            }
            if (!_AuthDBEntryObject.ContainsKey(AuthDBEntry.FINAL_ACCESS_SCOPE_PROPERTY))
            {
                _ErrorResponse = BWebResponse.NotFound("Given auth method does not contain any access scope.");
                return false;
            }
            return true;
        }

        private int FindIndexOfScopeInAuthDBEntryObject(out JArray _FinalAccessScopeArray, out AccessScope FinalAccessScope, JObject _AuthDBEntryObject_OnlyWithFinalAccessScope)
        {
            FinalAccessScope = null;

            int FoundIndex = -1, j = 0;
            _FinalAccessScopeArray = (JArray)_AuthDBEntryObject_OnlyWithFinalAccessScope[AuthDBEntry.FINAL_ACCESS_SCOPE_PROPERTY];
            foreach (var FinalAccessScopeObject in _FinalAccessScopeArray)
            {
                var FinalScope = JsonConvert.DeserializeObject<AccessScope>(FinalAccessScopeObject.ToString());
                if (FinalScope.WildcardPath == RequestedFinalRightWildcard)
                {
                    FinalAccessScope = FinalScope;
                    FoundIndex = j;
                    break;
                }
                j++;
            }
            return FoundIndex;
        }

        private BWebServiceResponse DeleteFinalRightForUserForAccessMethod(HttpListenerContext _Context, Action<string> _ErrorMessageAction)
        {
            if (!GetAuthDBEntryObject(out JObject AuthDBEntryObject, out BWebServiceResponse ErrorResponse, _ErrorMessageAction))
            {
                return ErrorResponse;
            }

            var FoundIndex = FindIndexOfScopeInAuthDBEntryObject(out JArray FinalAccessScopeArray, out AccessScope _, AuthDBEntryObject);
            if (FoundIndex == -1)
            {
                return BWebResponse.NotFound("Given auth method does not contain the given access right.");
            }

            FinalAccessScopeArray.RemoveAt(FoundIndex);

            var AuthDBEntryKey = new BPrimitiveType(RequestedAuthMethodKey);

            Controller_DeliveryEnsurer.Get().DB_UpdateItem_FireAndForget(
                _Context,
                AuthDBEntry.DBSERVICE_AUTHMETHODS_TABLE(),
                AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY,
                AuthDBEntryKey,
                AuthDBEntryObject);

            MemoryService.SetKeyValue(CommonData.MemoryQueryParameters,
                new Tuple<string, BPrimitiveType>[]
                {
                    new Tuple<string, BPrimitiveType>(AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY + AuthDBEntryKey.AsString, new BPrimitiveType(AuthDBEntryObject.ToString()))
                },
                _ErrorMessageAction);

            return BWebResponse.StatusOK("Final access right has been deleted.");
        }

        private BWebServiceResponse UpdateFinalRightForUserForAccessMethod(HttpListenerContext _Context, Action<string> _ErrorMessageAction)
        {
            var NewFinalScope = new AccessScope()
            {
                WildcardPath = RequestedFinalRightWildcard
            };

            using (var InputStream = _Context.Request.InputStream)
            {
                using (var ResponseReader = new StreamReader(InputStream))
                {
                    try
                    {
                        var NewRights = JArray.Parse(ResponseReader.ReadToEnd());
                        foreach (string Right in NewRights)
                        {
                            NewFinalScope.AccessRights.Add(Right);
                        }

                        for (int i = NewFinalScope.AccessRights.Count - 1; i >= 0; i--)
                        {
                            NewFinalScope.AccessRights[i] = NewFinalScope.AccessRights[i].ToUpper();
                            if (!AccessScopeLibrary.ACCESS_RIGHTS.Contains(NewFinalScope.AccessRights[i]))
                            {
                                NewFinalScope.AccessRights.RemoveAt(i);
                            }
                        }

                        if (NewFinalScope.AccessRights.Count > 0)
                        {
                            NewFinalScope.AccessRights = NewFinalScope.AccessRights.Distinct().ToList();
                        }
                        else return BWebResponse.BadRequest("Given access scope does not contain any valid right.");
                    }
                    catch (Exception e)
                    {
                        _ErrorMessageAction?.Invoke("User_UpdateDeleteRight_ForAccessRight_ForUser->UpdateFinalRightForUserForAccessMethod: Read request body stage has failed. Exception: " + e.Message + ", Trace: " + e.StackTrace);
                        return BWebResponse.BadRequest("Malformed request body. Request must be a valid json form.");
                    }
                }
            }

            var UserKey = new BPrimitiveType(RequestedUserID);
            if (!DatabaseService.GetItem(
                UserDBEntry.DBSERVICE_USERS_TABLE(),
                UserDBEntry.KEY_NAME_USER_ID,
                UserKey,
                UserDBEntry.Properties,
                out JObject UserObject,
                _ErrorMessageAction))
            {
                return BWebResponse.InternalError("Database fetch operation has failed");
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

            if (!AccessScopeLibrary.CheckBaseFinalFullContainment(BaseScopeList, new List<AccessScope>() { NewFinalScope }))
            {
                return BWebResponse.Forbidden("User does not have requested rights in user's base rights.");
            }

            if (!GetAuthDBEntryObject(out JObject AuthDBEntryObject, out BWebServiceResponse ErrorResponse, _ErrorMessageAction))
            {
                return ErrorResponse;
            }

            var FoundIndex = FindIndexOfScopeInAuthDBEntryObject(out JArray FinalAccessScopeArray, out AccessScope FinalAccessScope, AuthDBEntryObject);
            if (FoundIndex == -1)
            {
                return BWebResponse.NotFound("Given auth method does not contain the given access right.");
            }

            FinalAccessScopeArray[FoundIndex] = JObject.Parse(JsonConvert.SerializeObject(NewFinalScope));

            var AuthDBEntryKey = new BPrimitiveType(RequestedAuthMethodKey);

            Controller_DeliveryEnsurer.Get().DB_UpdateItem_FireAndForget(
                _Context,
                AuthDBEntry.DBSERVICE_AUTHMETHODS_TABLE(),
                AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY,
                AuthDBEntryKey,
                AuthDBEntryObject);

            MemoryService.SetKeyValue(CommonData.MemoryQueryParameters,
                new Tuple<string, BPrimitiveType>[]
                {
                    new Tuple<string, BPrimitiveType>(AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY + AuthDBEntryKey.AsString, new BPrimitiveType(AuthDBEntryObject.ToString()))
                },
                _ErrorMessageAction);

            return BWebResponse.StatusOK("Final access right has been updated.");
        }
    }
}