/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using AuthService.Endpoints.Structures;
using AuthService.Endpoints.Common;
using BCloudServiceUtilities;
using BCommonUtilities;
using BWebServiceUtilities;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Text.RegularExpressions;
using ServiceUtilities;
using ServiceUtilities.PubSubUsers.PubSubRelated;

namespace AuthService
{
    internal class User_UpdateDeleteBaseRight_ForUser : WebServiceBaseTimeoutableDeliveryEnsurerUser
    {
        private readonly IBDatabaseServiceInterface DatabaseService;
        private readonly IBMemoryServiceInterface MemoryService;
        private readonly string RestfulUrlParameter_UsersKey;
        private readonly string RestfulUrlParameter_BaseAccessRightsKey;

        private string RequestedUserID;
        private string RequestedBaseRightWildcard;
        private string RequestedBaseRightWildcard_Regex;

        public User_UpdateDeleteBaseRight_ForUser(IBDatabaseServiceInterface _DatabaseService, IBMemoryServiceInterface _MemoryService, string _RestfulUrlParameter_UsersKey, string _RestfulUrlParameter_BaseAccessRightsKey)
        {
            DatabaseService = _DatabaseService;
            MemoryService = _MemoryService;
            RestfulUrlParameter_UsersKey = _RestfulUrlParameter_UsersKey;
            RestfulUrlParameter_BaseAccessRightsKey = _RestfulUrlParameter_BaseAccessRightsKey;
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
                _ErrorMessageAction?.Invoke("User_UpdateDeleteBaseRight_ForUser: POST and DELETE methods are accepted. But received request method:  " + _Context.Request.HttpMethod);
                return BWebResponse.MethodNotAllowed("POST and DELETE methods are accepted. But received request method: " + _Context.Request.HttpMethod);
            }

            RequestedUserID = RestfulUrlParameters[RestfulUrlParameter_UsersKey];
            RequestedBaseRightWildcard = WebUtility.UrlDecode(RestfulUrlParameters[RestfulUrlParameter_BaseAccessRightsKey]);
            RequestedBaseRightWildcard_Regex = BUtility.WildCardToRegular(RequestedBaseRightWildcard);

            if (!Controller_AtomicDBOperation.Get().GetClearanceForDBOperation(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), RequestedUserID, _ErrorMessageAction))
            {
                return BWebResponse.InternalError("Atomic operation control has failed.");
            }

            BWebServiceResponse Result;
            if (_Context.Request.HttpMethod == "POST")
            {
                Result = UpdateBaseRightForUser(_Context, _ErrorMessageAction);
            }
            else
            {
                Result = DeleteBaseRightForUser(_Context, _ErrorMessageAction);
            }

            Controller_AtomicDBOperation.Get().SetClearanceForDBOperationForOthers(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), RequestedUserID, _ErrorMessageAction);

            return Result;
        }

        private BWebServiceResponse DeleteBaseRightForUser(HttpListenerContext _Context, Action<string> _ErrorMessageAction)
        {
            var UserKey = new BPrimitiveType(RequestedUserID);

            if (!DatabaseService.GetItem(
                UserDBEntry.DBSERVICE_USERS_TABLE(),
                UserDBEntry.KEY_NAME_USER_ID,
                UserKey,
                UserDBEntry.Properties,
                out JObject UserObject,
                _ErrorMessageAction))
            {
                return BWebResponse.InternalError("Database fetch-user-info operation has failed.");
            }
            if (UserObject == null)
            {
                return BWebResponse.NotFound("User does not exist.");
            }

            if (!UserObject.ContainsKey(UserDBEntry.BASE_ACCESS_SCOPE_PROPERTY))
            {
                return BWebResponse.NotFound("User does not have any base rights.");
            }
            var BaseAccessScopeAsArray = (JArray)UserObject[UserDBEntry.BASE_ACCESS_SCOPE_PROPERTY];
            var FetchedBaseAccessScopeList = new List<AccessScope>();

            //Check existence of access scope
            var ExistingAccessScopeIndex = -1;

            int j = 0;
            foreach (JObject BaseAccessScopeObject in BaseAccessScopeAsArray)
            {
                var Scope = JsonConvert.DeserializeObject<AccessScope>(BaseAccessScopeObject.ToString());
                FetchedBaseAccessScopeList.Add(Scope);

                //Checked
                if (ExistingAccessScopeIndex == -1 && Scope.WildcardPath == RequestedBaseRightWildcard)
                {
                    ExistingAccessScopeIndex = j;
                    break;
                }
                j++;
            }

            if (ExistingAccessScopeIndex == -1)
            {
                return BWebResponse.NotFound("User does not have the given base right.");
            }

            if (UserObject.ContainsKey(UserDBEntry.AUTH_METHODS_PROPERTY))
            {
                var AuthMethodsAsArray = (JArray)UserObject[UserDBEntry.AUTH_METHODS_PROPERTY];

                foreach (var AuthMethodToken in AuthMethodsAsArray)
                {
                    var AuthMethodObject = (JObject)AuthMethodToken;
                    var _AuthMethod = JsonConvert.DeserializeObject<AuthMethod>(AuthMethodObject.ToString());

                    BPrimitiveType AuthMethodKey = null;
                    switch (_AuthMethod.Method)
                    {
                        case AuthMethod.Methods.USER_EMAIL_PASSWORD_METHOD:
                            {
                                AuthMethodKey = new BPrimitiveType(_AuthMethod.UserEmail + _AuthMethod.PasswordMD5);
                                break;
                            }
                        case AuthMethod.Methods.USER_NAME_PASSWORD_METHOD:
                            {
                                AuthMethodKey = new BPrimitiveType(_AuthMethod.UserName + _AuthMethod.PasswordMD5);
                                break;
                            }
                        case AuthMethod.Methods.API_KEY_METHOD:
                            AuthMethodKey = new BPrimitiveType(_AuthMethod.ApiKey);
                            break;
                    }

                    if (DatabaseService.GetItem(
                            AuthDBEntry.DBSERVICE_AUTHMETHODS_TABLE(),
                            AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY,
                            AuthMethodKey,
                            AuthDBEntry.Properties,
                            out JObject AuthObject,
                            _ErrorMessageAction)
                        && AuthObject != null
                        && AuthObject.ContainsKey(AuthDBEntry.FINAL_ACCESS_SCOPE_PROPERTY))
                    {
                        bool bDeleteOccurredForMethod = false;

                        var AuthScopeEntriesAsArray = (JArray)AuthObject[AuthDBEntry.FINAL_ACCESS_SCOPE_PROPERTY];
                        var NewAuthScopeEntriesArray = new JArray();

                        foreach (JObject AuthScopeEntryObject in AuthScopeEntriesAsArray)
                        {
                            var ExistingScope = JsonConvert.DeserializeObject<AccessScope>(AuthScopeEntryObject.ToString());

                            bool bDelete = true;

                            //Checked
                            if (Regex.IsMatch(ExistingScope.WildcardPath, RequestedBaseRightWildcard_Regex))
                            {
                                //Check if it should still have the right due to other base rights
                                foreach (var FetchedBaseAccessScope in FetchedBaseAccessScopeList)
                                {
                                    //Checked
                                    if (ExistingScope.WildcardPath != FetchedBaseAccessScope.WildcardPath 
                                        && Regex.IsMatch(ExistingScope.WildcardPath, BUtility.WildCardToRegular(FetchedBaseAccessScope.WildcardPath)))
                                    {
                                        bool bRightCheck = true;
                                        foreach (var ExistingRight in ExistingScope.AccessRights)
                                        {
                                            if (!FetchedBaseAccessScope.AccessRights.Contains(ExistingRight))
                                            {
                                                bRightCheck = false;
                                                break;
                                            }
                                        }
                                        if (!bRightCheck) continue;
                                        
                                        bDelete = false;
                                        break;
                                    }
                                }
                            }
                            else
                            {
                                bDelete = false;
                            }

                            if (bDelete)
                            {
                                bDeleteOccurredForMethod = true;
                            }
                            else
                            {
                                NewAuthScopeEntriesArray.Add(AuthScopeEntryObject);
                            }
                        }

                        if (bDeleteOccurredForMethod)
                        {
                            AuthObject[AuthDBEntry.FINAL_ACCESS_SCOPE_PROPERTY] = NewAuthScopeEntriesArray;

                            Controller_DeliveryEnsurer.Get().DB_UpdateItem_FireAndForget(
                                _Context,
                                AuthDBEntry.DBSERVICE_AUTHMETHODS_TABLE(),
                                AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY,
                                AuthMethodKey,
                                AuthObject);

                            MemoryService.SetKeyValue(CommonData.MemoryQueryParameters,
                                new Tuple<string, BPrimitiveType>[]
                                {
                                    new Tuple<string, BPrimitiveType>(AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY + AuthMethodKey.AsString, new BPrimitiveType(AuthObject.ToString()))
                                },
                                _ErrorMessageAction);
                        }
                    }
                }
            }

            BaseAccessScopeAsArray.RemoveAt(ExistingAccessScopeIndex);
            UserObject[UserDBEntry.BASE_ACCESS_SCOPE_PROPERTY] = BaseAccessScopeAsArray;

            Controller_DeliveryEnsurer.Get().DB_UpdateItem_FireAndForget(
                _Context,
                UserDBEntry.DBSERVICE_USERS_TABLE(),
                UserDBEntry.KEY_NAME_USER_ID,
                UserKey,
                UserObject);

            return BWebResponse.StatusOK("Base right has been deleted.");
        }

        private BWebServiceResponse UpdateBaseRightForUser(HttpListenerContext _Context, Action<string> _ErrorMessageAction)
        {
            var NewRights = new List<string>();

            using (var InputStream = _Context.Request.InputStream)
            {
                using (var ResponseReader = new StreamReader(InputStream))
                {
                    try
                    {
                        var NewRightsArray = JArray.Parse(ResponseReader.ReadToEnd());
                        foreach (string NewRight in NewRightsArray)
                        {
                            var NewRightCaseCorrected = NewRight.ToUpper();
                            if (AccessScopeLibrary.ACCESS_RIGHTS.Contains(NewRightCaseCorrected))
                            {
                                NewRights.Add(NewRightCaseCorrected);
                            }
                        }
                        NewRights = NewRights.Distinct().ToList();
                        NewRights.Sort();
                    }
                    catch (Exception e)
                    {
                        _ErrorMessageAction?.Invoke("User_UpdateDeleteBaseRight_ForUser->UpdateBaseRightForUser: Read request body stage has failed. Exception: " + e.Message + ", Trace: " + e.StackTrace);
                        return BWebResponse.BadRequest("Malformed request body. Request must be a valid json form.");
                    }
                }
            }
            
            if (NewRights.Count == 0)
            {
                return BWebResponse.BadRequest("Request does not contain any valid access right. Use DELETE method for deleting the scope. Access rights can be: " + AccessScopeLibrary.GetPossibleAccessRightsText());
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
                return BWebResponse.InternalError("Database fetch-user-info operation has failed.");
            }
            if (UserObject == null)
            {
                return BWebResponse.NotFound("User does not exist.");
            }

            if (!UserObject.ContainsKey(UserDBEntry.BASE_ACCESS_SCOPE_PROPERTY))
            {
                return BWebResponse.NotFound("User does not have any base rights.");
            }

            var BaseAccessScopeAsArray = (JArray)UserObject[UserDBEntry.BASE_ACCESS_SCOPE_PROPERTY];
            var FetchedBaseAccessScopeList = new List<AccessScope>();

            //Check existence of access scope
            AccessScope ExistingAccessScope = null;
            int ExistingAccessScopeIndex = -1;

            int j = 0;
            foreach (JObject BaseAccessScopeObject in BaseAccessScopeAsArray)
            {
                var Scope = JsonConvert.DeserializeObject<AccessScope>(BaseAccessScopeObject.ToString());
                FetchedBaseAccessScopeList.Add(Scope);

                if (ExistingAccessScopeIndex == -1 && Scope.WildcardPath == RequestedBaseRightWildcard)
                {
                    ExistingAccessScope = Scope;
                    ExistingAccessScopeIndex = j;
                    break;
                }
                j++;
            }

            if (ExistingAccessScopeIndex == -1)
            {
                return BWebResponse.NotFound("User does not have the given base right.");
            }

            ExistingAccessScope.AccessRights.Sort();

            //Check if requested rights are different
            bool bDifferent = false;
            if (ExistingAccessScope.AccessRights.Count == NewRights.Count)
            {
                for (var i = 0; i < ExistingAccessScope.AccessRights.Count; i++)
                {
                    if (ExistingAccessScope.AccessRights[i] != NewRights[i])
                    {
                        bDifferent = true;
                        break;
                    }
                }
            }
            else
            {
                bDifferent = true;
            }

            if (bDifferent)
            {
                if (UserObject.ContainsKey(UserDBEntry.AUTH_METHODS_PROPERTY))
                {
                    var AuthMethodsAsArray = (JArray)UserObject[UserDBEntry.AUTH_METHODS_PROPERTY];

                    foreach (var AuthMethodToken in AuthMethodsAsArray)
                    {
                        var AuthMethodObject = (JObject)AuthMethodToken;
                        var MethodBase = JsonConvert.DeserializeObject<AuthMethod>(AuthMethodObject.ToString());

                        string PasswordMD5 = null;

                        BPrimitiveType AuthMethodKey = null;
                        switch (MethodBase.Method)
                        {
                            case AuthMethod.Methods.USER_EMAIL_PASSWORD_METHOD:
                                {
                                    PasswordMD5 = MethodBase.PasswordMD5;
                                    AuthMethodKey = new BPrimitiveType(MethodBase.UserEmail + PasswordMD5);
                                    break;
                                }
                            case AuthMethod.Methods.USER_NAME_PASSWORD_METHOD:
                                {
                                    PasswordMD5 = MethodBase.PasswordMD5;
                                    AuthMethodKey = new BPrimitiveType(MethodBase.UserName + PasswordMD5);
                                    break;
                                }
                            case AuthMethod.Methods.API_KEY_METHOD:
                                AuthMethodKey = new BPrimitiveType(MethodBase.ApiKey);
                                break;
                        }

                        if (DatabaseService.GetItem(
                                AuthDBEntry.DBSERVICE_AUTHMETHODS_TABLE(),
                                AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY,
                                AuthMethodKey,
                                AuthDBEntry.Properties,
                                out JObject AuthObject,
                                _ErrorMessageAction)
                            && AuthObject != null
                            && AuthObject.ContainsKey(AuthDBEntry.FINAL_ACCESS_SCOPE_PROPERTY))
                        {
                            bool bChangeOccurredForMethod = false;

                            var AuthScopeEntriesAsArray = (JArray)AuthObject[AuthDBEntry.FINAL_ACCESS_SCOPE_PROPERTY];
                            var NewAuthScopeEntriesArray = new JArray();

                            foreach (JObject AuthScopeEntryObject in AuthScopeEntriesAsArray)
                            {
                                bool bChangeOccurredForScope = false;
                                var ExistingScope = JsonConvert.DeserializeObject<AccessScope>(AuthScopeEntryObject.ToString());

                                //Checked
                                if (Regex.IsMatch(ExistingScope.WildcardPath, RequestedBaseRightWildcard_Regex))
                                {
                                    for (var i = (ExistingScope.AccessRights.Count - 1); i >= 0; i--)
                                    {
                                        if (!NewRights.Contains(ExistingScope.AccessRights[i]))
                                        {
                                            bool bFoundInOther = false;

                                            //Check if it should still have the right due to other base rights
                                            foreach (var FetchedBaseAccessScope in FetchedBaseAccessScopeList)
                                            {
                                                //Checked
                                                if (ExistingScope.WildcardPath != FetchedBaseAccessScope.WildcardPath
                                                    && Regex.IsMatch(ExistingScope.WildcardPath, BUtility.WildCardToRegular(FetchedBaseAccessScope.WildcardPath))
                                                    && FetchedBaseAccessScope.AccessRights.Contains(ExistingScope.AccessRights[i]))
                                                {
                                                    bFoundInOther = true;
                                                    break;
                                                }
                                            }

                                            if (!bFoundInOther)
                                            {
                                                ExistingScope.AccessRights.RemoveAt(i);
                                                bChangeOccurredForScope = true;
                                                bChangeOccurredForMethod = true;
                                            }
                                        }
                                    }
                                }

                                if (bChangeOccurredForScope)
                                {
                                    NewAuthScopeEntriesArray.Add(JObject.Parse(JsonConvert.SerializeObject(ExistingScope)));
                                }
                                else
                                {
                                    NewAuthScopeEntriesArray.Add(AuthScopeEntryObject);
                                }
                            }

                            if (bChangeOccurredForMethod)
                            {
                                AuthObject[AuthDBEntry.FINAL_ACCESS_SCOPE_PROPERTY] = NewAuthScopeEntriesArray;

                                Controller_DeliveryEnsurer.Get().DB_UpdateItem_FireAndForget(
                                    _Context,
                                    AuthDBEntry.DBSERVICE_AUTHMETHODS_TABLE(),
                                    AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY,
                                    AuthMethodKey,
                                    AuthObject);

                                MemoryService.SetKeyValue(CommonData.MemoryQueryParameters,
                                    new Tuple<string, BPrimitiveType>[]
                                    {
                                        new Tuple<string, BPrimitiveType>(AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY + AuthMethodKey.AsString, new BPrimitiveType(AuthObject.ToString()))
                                    },
                                    _ErrorMessageAction);
                            }
                        }
                    }
                }

                ExistingAccessScope.AccessRights = NewRights;
                BaseAccessScopeAsArray[ExistingAccessScopeIndex] = JObject.Parse(JsonConvert.SerializeObject(ExistingAccessScope));

                UserObject[UserDBEntry.BASE_ACCESS_SCOPE_PROPERTY] = BaseAccessScopeAsArray;

                Controller_DeliveryEnsurer.Get().DB_UpdateItem_FireAndForget(
                    _Context,
                    UserDBEntry.DBSERVICE_USERS_TABLE(),
                    UserDBEntry.KEY_NAME_USER_ID,
                    UserKey,
                    UserObject);
            }

            return BWebResponse.StatusOK("Base right has been updated.");
        }
    }
}