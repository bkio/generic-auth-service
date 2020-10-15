/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System;
using System.Collections.Generic;
using System.Net;
using AuthService.Endpoints.Common;
using AuthService.Endpoints.Controllers;
using AuthService.Endpoints.Structures;
using BCloudServiceUtilities;
using BCommonUtilities;
using BWebServiceUtilities;
using BWebServiceUtilities_GC;
using ServiceUtilities;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AuthService.Endpoints
{
    partial class InternalCalls
    {
        internal class CleanupCall : InternalWebServiceBaseTimeoutable
        {
            private readonly IBDatabaseServiceInterface DatabaseService;
            private readonly IBMemoryServiceInterface MemoryService;

            public CleanupCall(string _InternalCallPrivateKey, IBDatabaseServiceInterface _DatabaseService, IBMemoryServiceInterface _MemoryService) : base(_InternalCallPrivateKey)
            {
                DatabaseService = _DatabaseService;
                MemoryService = _MemoryService;
            }

            public override BWebServiceResponse OnRequest_Interruptable(HttpListenerContext _Context, Action<string> _ErrorMessageAction = null)
            {
                Cleanup_AuthMethods(_ErrorMessageAction);
                Cleanup_UniqueUserFields(_ErrorMessageAction);
                Cleanup_UserModels(_Context, _ErrorMessageAction);

                return BWebResponse.StatusOK("OK.");
            }

            private void Cleanup_UserModels(HttpListenerContext _Context, Action<string> _ErrorMessageAction = null)
            {
                if (!DatabaseService.ScanTable(
                    UserDBEntry.DBSERVICE_USERS_TABLE(),
                    out List<JObject> UserEntries,
                    _ErrorMessageAction))
                {
                    _ErrorMessageAction?.Invoke("Cleanup_UserModels: Table does not exist or ScanTable operation has failed.");
                    return;
                }
                if (UserEntries.Count == 0)
                {
                    return;
                }

                //Get cad file service endpoint from internal set state
                if (!InternalSetState.GetValueFromMemoryService(
                    out string CADFileServiceEndpoint,
                    InternalSetState.CAD_FILE_SERVICE_ENDPOINT_PROPERTY,
                    MemoryService,
                    (string _Message) =>
                    {
                        _ErrorMessageAction?.Invoke("Cleanup_UserModels: Unable to get CadFileServiceEndpoint: " + _Message);
                    }))
                {
                    return;
                }

                foreach (var UserJObject in UserEntries)
                {
                    var UserID = (string)UserJObject[UserDBEntry.KEY_NAME_USER_ID];
                    if (!Controller_AtomicDBOperation.Get().GetClearanceForDBOperation(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), UserID, _ErrorMessageAction))
                    {
                        continue;
                    }
                    try
                    {
                        var UserID_Primitive = new BPrimitiveType(UserID);

                        var UserDeserialized = JsonConvert.DeserializeObject<UserDBEntry>(UserJObject.ToString());

                        var UserModelIDsJArray = new JArray();
                        var UserSharedModelIDsJArray = new JArray();

                        foreach (var CurrentModel in UserDeserialized.UserModels)
                        {
                            UserModelIDsJArray.Add(CurrentModel);
                        }

                        foreach (var CurrentSharedModel in UserDeserialized.UserSharedModels)
                        {
                            UserSharedModelIDsJArray.Add(CurrentSharedModel);
                        }

                        var RequestObject = new JObject()
                        {
                            ["userModelIds"] = UserModelIDsJArray,
                            ["userSharedModelIds"] = UserSharedModelIDsJArray
                        };

                        // file/internal/check_models_exist will return CheckedUserModelIDs and CheckedUserSharedModelIDs list
                        List<string> CheckedUserModelIDs = new List<string>();
                        List<string> CheckedUserSharedModelIDs = new List<string>();

                        GetTracingService()?.On_FromServiceToService_Sent(_Context, _ErrorMessageAction);

                        var Result = BWebUtilities_GC_CloudRun.InterServicesRequest(new BWebUtilities_GC_CloudRun.InterServicesRequestRequest()
                        {
                            DestinationServiceUrl = CADFileServiceEndpoint + "/file/internal/check_models_exist?secret=" + InternalCallPrivateKey,
                            RequestMethod = "POST",
                            bWithAuthToken = true,
                            UseContextHeaders = _Context,
                            ContentType = "application/json",
                            Content = new BStringOrStream(RequestObject.ToString()),
                            ExcludeHeaderKeysForRequest = null
                        },
                        false,
                        _ErrorMessageAction);

                        GetTracingService()?.On_FromServiceToService_Received(_Context, _ErrorMessageAction);

                        string ResponseContentAsString = "";
                        JObject ResponseContentAsJson = null;
                        try
                        {
                            ResponseContentAsString = Result.Content.String;
                            ResponseContentAsJson = JObject.Parse(ResponseContentAsString);

                            var ArrayUserModelsTmp = (JArray)ResponseContentAsJson["checkedUserModelIds"];
                            if (ArrayUserModelsTmp != null)
                            {
                                foreach (var Tmp in ArrayUserModelsTmp)
                                {
                                    CheckedUserModelIDs.Add((string)Tmp);
                                }
                            }

                            var ArraySharedUserModelsTmp = (JArray)ResponseContentAsJson["checkedUserSharedModelIds"];
                            if (ArraySharedUserModelsTmp != null)
                            {
                                foreach (var Tmp in ArraySharedUserModelsTmp)
                                {
                                    CheckedUserSharedModelIDs.Add((string)Tmp);
                                }
                            }
                        }
                        catch (Exception e)
                        {
                            _ErrorMessageAction?.Invoke("Cleanup_UserModels: Error occurred during reading response/parsing json: " + e.Message + ", trace: " + e.StackTrace + ", response content: " + ResponseContentAsString + ", response code: " + Result.ResponseCode);
                            continue;
                        }

                        if (!Result.bSuccess || Result.ResponseCode >= 400)
                        {
                            _ErrorMessageAction?.Invoke("Cleanup_UserModels: Request did not end up with success. Response content: " + ResponseContentAsString + ", response code: " + Result.ResponseCode);
                            continue;
                        }

                        UserDeserialized.UserModels = new List<string>(CheckedUserModelIDs);
                        UserDeserialized.UserSharedModels = new List<string>(CheckedUserSharedModelIDs);

                        if (!DatabaseService.UpdateItem(//Fire and forget is not suitable here since there are following calls after DB update which will change the DB structure
                                UserDBEntry.DBSERVICE_USERS_TABLE(),
                                UserDBEntry.KEY_NAME_USER_ID,
                                UserID_Primitive,
                                JObject.Parse(JsonConvert.SerializeObject(UserDeserialized)),
                                out JObject _, EBReturnItemBehaviour.DoNotReturn, null,
                                _ErrorMessageAction))
                        {
                            continue;
                        }
                    }
                    finally
                    {
                        Controller_AtomicDBOperation.Get().SetClearanceForDBOperationForOthers(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), UserID, _ErrorMessageAction);
                    }
                }
            }

            private void Cleanup_AuthMethods(Action<string> _ErrorMessageAction = null)
            {
                if (!DatabaseService.ScanTable(
                    AuthDBEntry.DBSERVICE_AUTHMETHODS_TABLE(),
                    out List<JObject> AuthEntries,
                    _ErrorMessageAction))
                {
                    _ErrorMessageAction?.Invoke("Cleanup_AuthMethods: Table does not exist or ScanTable operation has failed.");
                    return;
                }
                if (AuthEntries.Count == 0)
                {
                    return;
                }

                foreach (var Current in AuthEntries)
                {
                    var Casted = JsonConvert.DeserializeObject<AuthDBEntry>(Current.ToString());
                    var EntryKey = (string)Current[AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY];

                    if (!Controller_AtomicDBOperation.Get().GetClearanceForDBOperation(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), Casted.UserID, _ErrorMessageAction))
                    {
                        continue;
                    }
                    try
                    {
                        bool bDeleteEntry = false;

                        if (!DatabaseService.GetItem(
                            UserDBEntry.DBSERVICE_USERS_TABLE(),
                            UserDBEntry.KEY_NAME_USER_ID,
                            new BPrimitiveType(Casted.UserID),
                            UserDBEntry.Properties,
                            out JObject UserObject,
                            _ErrorMessageAction))
                        {
                            continue;
                        }
                        if (UserObject == null)
                        {
                            //User does not exist
                            bDeleteEntry = true;
                        }
                        else
                        {
                            bool bFound = false;
                            bool bSSOMethod = false;
                            bool bSSORefreshTokenExpired = false;

                            var User = JsonConvert.DeserializeObject<UserDBEntry>(UserObject.ToString());
                            for (var i = 0; i < User.AuthMethods.Count; i++)
                            {
                                var UserAuthMethod = User.AuthMethods[i];
                                var UserAuthMethodKey = "";

                                if (UserAuthMethod.Method == AuthMethod.Methods.USER_EMAIL_PASSWORD_METHOD)
                                {
                                    if (UserAuthMethod.UserEmail == null || UserAuthMethod.PasswordMD5 == null || UserAuthMethod.UserEmail.Length == 0 || UserAuthMethod.PasswordMD5.Length == 0) continue;
                                    UserAuthMethodKey = UserAuthMethod.UserEmail + UserAuthMethod.PasswordMD5;

                                    if (UserAuthMethodKey == EntryKey)
                                    {
                                        bFound = true;

                                        //SSO Auth Method Expiry Check
                                        if (UserAuthMethod.UserEmail.EndsWith(Controller_SSOAccessToken.EMAIL_USER_NAME_POSTFIX))
                                        {
                                            bSSOMethod = true;

                                            var QueryParameters = Controller_SSOAccessToken.MakeSSOQueryParameters(UserAuthMethod.PasswordMD5);
                                            if (Controller_SSOAccessToken.IsTokenExpiredOrInvalid(out Dictionary<string, BPrimitiveType> _Result, MemoryService, QueryParameters, _ErrorMessageAction)
                                                || _Result == null)
                                            {

                                                bSSORefreshTokenExpired = true;
                                                User.AuthMethods.RemoveAt(i);
                                            }
                                        }
                                        break;
                                    }
                                }
                                else
                                {
                                    if (UserAuthMethod.Method == AuthMethod.Methods.USER_NAME_PASSWORD_METHOD)
                                    {
                                        if (UserAuthMethod.UserName == null || UserAuthMethod.PasswordMD5 == null || UserAuthMethod.UserName.Length == 0 || UserAuthMethod.PasswordMD5.Length == 0) continue;
                                        UserAuthMethodKey = UserAuthMethod.UserName + UserAuthMethod.PasswordMD5;
                                    }
                                    else if (UserAuthMethod.Method == AuthMethod.Methods.API_KEY_METHOD)
                                    {
                                        UserAuthMethodKey = UserAuthMethod.ApiKey;
                                    }

                                    if (UserAuthMethodKey == EntryKey)
                                    {
                                        bFound = true;
                                        break;
                                    }
                                }
                            }
                            if (!bFound)
                            {
                                bDeleteEntry = true;
                            }
                            else if (bSSOMethod && bSSORefreshTokenExpired)
                            {
                                _ErrorMessageAction?.Invoke("Cleanup_AuthMethods: Expired sso auth method has been found. Deleting the entry.");
                                bDeleteEntry = true;

                                DatabaseService.UpdateItem(
                                    UserDBEntry.DBSERVICE_USERS_TABLE(),
                                    UserDBEntry.KEY_NAME_USER_ID,
                                    new BPrimitiveType(Casted.UserID),
                                    JObject.Parse(JsonConvert.SerializeObject(User)),
                                    out JObject _,
                                    EBReturnItemBehaviour.DoNotReturn,
                                    null,
                                    _ErrorMessageAction);
                            }
                        }

                        if (bDeleteEntry)
                        {
                            DatabaseService.DeleteItem(
                                AuthDBEntry.DBSERVICE_AUTHMETHODS_TABLE(),
                                AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY,
                                new BPrimitiveType(EntryKey),
                                out JObject _,
                                EBReturnItemBehaviour.DoNotReturn,
                                _ErrorMessageAction);

                            MemoryService.DeleteKey(
                                CommonData.MemoryQueryParameters,
                                AuthDBEntry.KEY_NAME_AUTH_DB_ENTRY + EntryKey,
                                _ErrorMessageAction);
                        }
                    }
                    finally
                    {
                        Controller_AtomicDBOperation.Get().SetClearanceForDBOperationForOthers(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), Casted.UserID, _ErrorMessageAction);
                    }
                }
            }

            private void Cleanup_UniqueUserFields(Action<string> _ErrorMessageAction = null)
            {
                if (!DatabaseService.ScanTable(
                    UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(),
                    out List<JObject> UniqueFieldsEntries,
                    _ErrorMessageAction))
                {
                    _ErrorMessageAction?.Invoke("Cleanup_UniqueUserFields: Table does not exist or ScanTable operation has failed.");
                    return;
                }
                if (UniqueFieldsEntries.Count == 0)
                {
                    return;
                }

                foreach (var Current in UniqueFieldsEntries)
                {
                    if (!Current.ContainsKey(UserDBEntry.KEY_NAME_USER_ID)) continue;

                    var UserID = (string)Current[UserDBEntry.KEY_NAME_USER_ID];

                    var EntryKeyName = "";
                    if (Current.ContainsKey(UniqueUserFieldsDBEntry.KEY_NAME_USER_EMAIL))
                    {
                        EntryKeyName = UniqueUserFieldsDBEntry.KEY_NAME_USER_EMAIL;
                    }
                    else if (Current.ContainsKey(UniqueUserFieldsDBEntry.KEY_NAME_USER_NAME))
                    {
                        EntryKeyName = UniqueUserFieldsDBEntry.KEY_NAME_USER_NAME;
                    }
                    else if (Current.ContainsKey(UniqueUserFieldsDBEntry.KEY_NAME_API_KEY))
                    {
                        EntryKeyName = UniqueUserFieldsDBEntry.KEY_NAME_API_KEY;
                    }
                    else continue;

                    var EntryKeyValue = (string)Current[EntryKeyName];
                    var ClearanceFullEntryKey = EntryKeyName + ":" + EntryKeyValue;

                    bool bRelease_UserEntry = false;
                    bool bRelease_UniqueFieldEntry = false;

                    try
                    {
                        if (!Controller_AtomicDBOperation.Get().GetClearanceForDBOperation(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), UserID, _ErrorMessageAction))
                        {
                            continue;
                        }
                        bRelease_UserEntry = true;

                        if (!Controller_AtomicDBOperation.Get().GetClearanceForDBOperation(InnerProcessor, UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(), ClearanceFullEntryKey, _ErrorMessageAction))
                        {
                            continue;
                        }
                        bRelease_UniqueFieldEntry = true;

                        bool bDeleteEntry = false;

                        if (!DatabaseService.GetItem(
                            UserDBEntry.DBSERVICE_USERS_TABLE(),
                            UserDBEntry.KEY_NAME_USER_ID,
                            new BPrimitiveType(UserID),
                            UserDBEntry.Properties,
                            out JObject UserObject,
                            _ErrorMessageAction))
                        {
                            continue;
                        }
                        if (UserObject == null)
                        {
                            //User does not exist
                            bDeleteEntry = true;
                        }
                        else
                        {
                            var User = JsonConvert.DeserializeObject<UserDBEntry>(UserObject.ToString());

                            switch (EntryKeyName)
                            {
                                case UniqueUserFieldsDBEntry.KEY_NAME_USER_EMAIL:
                                    bDeleteEntry = EntryKeyValue != User.UserEmail;
                                    break;
                                case UniqueUserFieldsDBEntry.KEY_NAME_USER_NAME:
                                    bDeleteEntry = EntryKeyValue != User.UserName;
                                    break;
                                case UniqueUserFieldsDBEntry.KEY_NAME_API_KEY:
                                    bool bFound = false;
                                    foreach (var UserAuthMethod in User.AuthMethods)
                                    {
                                        if (UserAuthMethod.Method == AuthMethod.Methods.API_KEY_METHOD)
                                        {
                                            if (UserAuthMethod.ApiKey == EntryKeyValue)
                                            {
                                                bFound = true;
                                                break;
                                            }
                                        }
                                    }
                                    if (!bFound)
                                    {
                                        bDeleteEntry = true;
                                    }
                                    break;
                            }
                        }

                        if (bDeleteEntry)
                        {
                            DatabaseService.DeleteItem(
                                UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(),
                                EntryKeyName,
                                new BPrimitiveType(EntryKeyValue),
                                out JObject _,
                                EBReturnItemBehaviour.DoNotReturn,
                                _ErrorMessageAction);
                        }
                    }
                    finally
                    {
                        if (bRelease_UniqueFieldEntry)
                        {
                            Controller_AtomicDBOperation.Get().SetClearanceForDBOperationForOthers(InnerProcessor, UniqueUserFieldsDBEntry.DBSERVICE_UNIQUEUSERFIELDS_TABLE(), ClearanceFullEntryKey, _ErrorMessageAction);
                        }
                        if (bRelease_UserEntry)
                        {
                            Controller_AtomicDBOperation.Get().SetClearanceForDBOperationForOthers(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), UserID, _ErrorMessageAction);
                        }
                    }
                }
            }
        }
    }
}