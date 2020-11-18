/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
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
    internal class User_AddListBaseRights_ForUser : WebServiceBaseTimeoutableDeliveryEnsurerUser
    {
        private readonly IBDatabaseServiceInterface DatabaseService;
        private readonly IBMemoryServiceInterface MemoryService;
        private readonly string RestfulUrlParameter_UsersKey;

        private string RequestedUserID;

        public User_AddListBaseRights_ForUser(IBDatabaseServiceInterface _DatabaseService, IBMemoryServiceInterface _MemoryService, string _RestfulUrlParameter_UsersKey)
        {
            DatabaseService = _DatabaseService;
            MemoryService = _MemoryService;
            RestfulUrlParameter_UsersKey = _RestfulUrlParameter_UsersKey;
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
                _ErrorMessageAction?.Invoke("User_AddListBaseRights_ForUser: GET and PUT methods are accepted. But received request method:  " + _Context.Request.HttpMethod);
                return BWebResponse.MethodNotAllowed("GET and PUT methods are accepted. But received request method: " + _Context.Request.HttpMethod);
            }

            RequestedUserID = RestfulUrlParameters[RestfulUrlParameter_UsersKey];

            if (_Context.Request.HttpMethod == "GET")
            {
                return ListBaseRightsForUser(_ErrorMessageAction);
            }
            //else
            {
                if (!Controller_AtomicDBOperation.Get().GetClearanceForDBOperation(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), RequestedUserID, _ErrorMessageAction))
                {
                    return BWebResponse.InternalError("Atomic operation control has failed.");
                }

                var Result = AddUpdateBaseRightsForUser(_Context, _ErrorMessageAction);

                Controller_AtomicDBOperation.Get().SetClearanceForDBOperationForOthers(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), RequestedUserID, _ErrorMessageAction);

                return Result;
            }
        }

        private BWebServiceResponse AddUpdateBaseRightsForUser(HttpListenerContext _Context, Action<string> _ErrorMessageAction)
        {
            var NewBaseScopeListFromRequest = new List<AccessScope>();

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
                                NewBaseScopeListFromRequest.Add(ConvertedScope);
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        _ErrorMessageAction?.Invoke("User_AddListBaseRights_ForUser->AddUpdateBaseRightsForUser: Read request body stage has failed. Exception: " + e.Message + ", Trace: " + e.StackTrace);
                        return BWebResponse.BadRequest("Malformed request body. Request must be a valid json form.");
                    }
                }
            }
            
            if (NewBaseScopeListFromRequest.Count == 0)
            {
                return BWebResponse.BadRequest("Request does not contain any valid base scope. Access rights can be: " + AccessScopeLibrary.GetPossibleAccessRightsText());
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

            var NewBaseAccessScopeAsJArray = new JArray();
            var NewBaseAccessScopeAsList = new List<AccessScope>();
            
            bool bUpdateOccurredForUserEntry = false;

            if (UserObject.ContainsKey(UserDBEntry.BASE_ACCESS_SCOPE_PROPERTY))
            {
                var BaseAccessScopeAsArray = (JArray)UserObject[UserDBEntry.BASE_ACCESS_SCOPE_PROPERTY];

                foreach (var NewScope in NewBaseScopeListFromRequest)
                {
                    bool bNewScopeFoundInExisting = false;

                    NewScope.AccessRights.Sort();

                    foreach (JObject ExistingScopeObject in BaseAccessScopeAsArray)
                    {
                        bool bChangeOccurredForScope = false;

                        var ExistingScope = JsonConvert.DeserializeObject<AccessScope>(ExistingScopeObject.ToString());
                        ExistingScope.AccessRights.Sort();

                        if (!bNewScopeFoundInExisting && ExistingScope.WildcardPath == NewScope.WildcardPath)
                        {
                            bNewScopeFoundInExisting = true;

                            if (NewScope.AccessRights.Count != ExistingScope.AccessRights.Count)
                            {
                                bUpdateOccurredForUserEntry = true;
                                NewBaseAccessScopeAsList.Add(NewScope);
                                NewBaseAccessScopeAsJArray.Add(JObject.Parse(JsonConvert.SerializeObject(NewScope)));
                                break;
                            }
                            else
                            {
                                bool bLocalChangeExists = false;

                                for (int i = 0; i < NewScope.AccessRights.Count; i++)
                                {
                                    if (NewScope.AccessRights[i] != ExistingScope.AccessRights[i])
                                    {
                                        bLocalChangeExists = true;
                                        break;
                                    }
                                }

                                if (bLocalChangeExists)
                                {
                                    bUpdateOccurredForUserEntry = true;
                                    bChangeOccurredForScope = true;
                                    NewBaseAccessScopeAsList.Add(NewScope);
                                    NewBaseAccessScopeAsJArray.Add(JObject.Parse(JsonConvert.SerializeObject(NewScope)));
                                }
                            }
                        }

                        if (!bChangeOccurredForScope)
                        {
                            NewBaseAccessScopeAsList.Add(ExistingScope);
                            NewBaseAccessScopeAsJArray.Add(ExistingScopeObject);
                        }
                    }

                    if (!bNewScopeFoundInExisting)
                    {
                        NewBaseAccessScopeAsList.Add(NewScope);
                        NewBaseAccessScopeAsJArray.Add(JObject.Parse(JsonConvert.SerializeObject(NewScope)));
                        bUpdateOccurredForUserEntry = true;
                    }
                }
            }

            if (bUpdateOccurredForUserEntry)
            {
                UserObject[UserDBEntry.BASE_ACCESS_SCOPE_PROPERTY] = NewBaseAccessScopeAsJArray;

                MemoryService.SetKeyValue(CommonData.MemoryQueryParameters, new Tuple<string, BPrimitiveType>[]
                {
                    new Tuple<string, BPrimitiveType>(
                        UserBaseAccessMEntry.M_KEY_NAME_USER_ID + RequestedUserID,
                        new BPrimitiveType(JsonConvert.SerializeObject(new UserBaseAccessMEntry()
                        {
                            BaseAccessScope = NewBaseAccessScopeAsList
                        })))
                }, _ErrorMessageAction);

                Controller_DeliveryEnsurer.Get().DB_UpdateItem_FireAndForget(
                    _Context,
                    UserDBEntry.DBSERVICE_USERS_TABLE(),
                    UserDBEntry.KEY_NAME_USER_ID,
                    UserKey,
                    UserObject);
            }

            return BWebResponse.StatusCreated("New base rights have been added.");
        }

        private BWebServiceResponse ListBaseRightsForUser(Action<string> _ErrorMessageAction)
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

            JArray BaseScopeArray;
            if (UserObject.ContainsKey(UserDBEntry.BASE_ACCESS_SCOPE_PROPERTY))
            {
                BaseScopeArray = (JArray)UserObject[UserDBEntry.BASE_ACCESS_SCOPE_PROPERTY];
            }
            else
            {
                BaseScopeArray = new JArray();
            }

            return BWebResponse.StatusOK("List base rights operation has succeeded.", new JObject()
            {
                [UserDBEntry.BASE_ACCESS_SCOPE_PROPERTY] = BaseScopeArray
            });
        }
    }
}