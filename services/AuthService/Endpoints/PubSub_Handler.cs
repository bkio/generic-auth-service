/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using AuthService.Endpoints.Controllers;
using AuthService.Endpoints.Structures;
using BCloudServiceUtilities;
using BCommonUtilities;
using ServiceUtilities;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AuthService.Endpoints
{
    partial class InternalCalls
    {
        internal class PubSub_To_AuthService : PubSubServiceBaseTimeoutableDeliveryEnsurerUser
        {
            private readonly IBDatabaseServiceInterface DatabaseService;

            public PubSub_To_AuthService(string _InternalCallPrivateKey, IBDatabaseServiceInterface _DatabaseService) : base(_InternalCallPrivateKey)
            {
                DatabaseService = _DatabaseService;
            }

            protected override bool Handle(HttpListenerContext _Context, ServiceUtilities.Action _Action, Action<string> _ErrorMessageAction = null)
            {
                if (_Action.GetActionType() == Actions.EAction.ACTION_AUTH_SERVICE_DELIVERY_ENSURER)
                {
                    Controller_DeliveryEnsurer.Get().Retry_FireAndForget_Operation(_Context, (Action_DeliveryEnsurer)_Action, _ErrorMessageAction);
                }
                else if (_Action.GetActionType() == Actions.EAction.ACTION_MODEL_CREATED 
                    || _Action.GetActionType() == Actions.EAction.ACTION_MODEL_DELETED)
                {
                    return UserCreatedDeletedModel(_Context, (Action_ModelAction)_Action, _ErrorMessageAction);
                }
                else if ( _Action.GetActionType() == Actions.EAction.ACTION_MODEL_SHARED_WITH_USER_IDS_CHANGED)
                {
                    return ModelSharingChanged((Action_ModelSharedWithUserIdsChanged)_Action, _ErrorMessageAction);
                }
                //else: Other auth service related actions

                return true;
            }

            private bool ModelSharingChanged(Action_ModelSharedWithUserIdsChanged _Action, Action<string> _ErrorMessageAction = null)
            {
                var OldHasStar = _Action.OldModelSharedWithUserIDs.Contains("*");
                var NewHasStar = _Action.ModelSharedWithUserIDs.Contains("*");

                //Check if old and new both have *
                if (OldHasStar && NewHasStar) return true;

                var UsersListJObject = new List<JObject>();
                if (OldHasStar || NewHasStar)
                {
                    if (!DatabaseService.ScanTable(UserDBEntry.DBSERVICE_USERS_TABLE(), out UsersListJObject, _ErrorMessageAction))
                    {
                        _ErrorMessageAction?.Invoke("InternalCalls->PubSub_To_AuthService->ModelSharingChanged: ScanTable has failed.");
                        return false; //Internal error, return error for retrial.
                    }
                    if (UsersListJObject.Count == 0) return true;
                }

                var ToBeAddedUsers = new List<string>();
                var ToBeRemovedUsers = new List<string>();

                //Check if old contains * but not the new
                if (OldHasStar && !NewHasStar)
                {
                    foreach (var UserObject in UsersListJObject)
                    {
                        if (UserObject != null && UserObject.ContainsKey(UserDBEntry.KEY_NAME_USER_ID))
                        {
                            var UserId = (string)UserObject[UserDBEntry.KEY_NAME_USER_ID];

                            if (!_Action.ModelSharedWithUserIDs.Contains(UserId))
                            {
                                ToBeRemovedUsers.Add(UserId);
                            }
                            else
                            {
                                ToBeAddedUsers.Add(UserId);
                            }
                        }
                    }
                }
                //Check if new contains * but not the old
                else if (!OldHasStar && NewHasStar)
                {
                    foreach (var UserObject in UsersListJObject)
                    {
                        if (UserObject != null && UserObject.ContainsKey(UserDBEntry.KEY_NAME_USER_ID))
                        {
                            ToBeAddedUsers.Add((string)UserObject[UserDBEntry.KEY_NAME_USER_ID]);
                        }
                    }
                }
                //None has star
                else
                {
                    var AlreadyFetchedUserObjects = new Dictionary<string, UserDBEntry>();
                    foreach (var OldUserId in _Action.OldModelSharedWithUserIDs)
                    {
                        if (!_Action.ModelSharedWithUserIDs.Contains(OldUserId))
                        {
                            //Just to check existence we only get the id as property
                            if (!DatabaseService.GetItem(UserDBEntry.DBSERVICE_USERS_TABLE(), UserDBEntry.KEY_NAME_USER_ID, new BPrimitiveType(OldUserId), new string[] { UserDBEntry.KEY_NAME_USER_ID }, out JObject UserObject, _ErrorMessageAction))
                            {
                                _ErrorMessageAction?.Invoke("InternalCalls->PubSub_To_AuthService->ModelSharingChanged: GetItem for " + UserDBEntry.KEY_NAME_USER_ID + ": " + OldUserId + " has failed.");
                                return false; //Internal error, return error for retrial.
                            }
                            if (UserObject == null) continue;

                            ToBeRemovedUsers.Add(OldUserId);
                        }
                    }
                    foreach (var NewUserId in _Action.ModelSharedWithUserIDs)
                    {
                        if (!_Action.OldModelSharedWithUserIDs.Contains(NewUserId))
                        {
                            if (!ToBeRemovedUsers.Remove(NewUserId))
                            {
                                //Just to check existence we only get the id as property
                                if (!DatabaseService.GetItem(UserDBEntry.DBSERVICE_USERS_TABLE(), UserDBEntry.KEY_NAME_USER_ID, new BPrimitiveType(NewUserId), new string[] { UserDBEntry.KEY_NAME_USER_ID }, out JObject UserObject, _ErrorMessageAction))
                                {
                                    _ErrorMessageAction?.Invoke("InternalCalls->PubSub_To_AuthService->ModelSharingChanged: GetItem for " + UserDBEntry.KEY_NAME_USER_ID + ": " + NewUserId + " has failed.");
                                    return false; //Internal error, return error for retrial.
                                }
                                if (UserObject == null) continue;
                            }

                            ToBeAddedUsers.Add(NewUserId);
                        }
                    }
                }

                //Do not play with owner's rights
                ToBeAddedUsers.Remove(_Action.UserID);
                ToBeRemovedUsers.Remove(_Action.UserID);

                //No changes need to be made
                if (ToBeAddedUsers.Count == 0 && ToBeRemovedUsers.Count == 0) return true;

                var PathsRegex = new Tuple<string, List<string>>[]
                {
                    new Tuple<string, List<string>>("/file/models/" + _Action.ModelID + "*", new List<string>() { "GET" }), //Only view access
                    new Tuple<string, List<string>>("/custom_procedures/by_model/" + _Action.ModelID + "*", new List<string>() { "GET" }), //Only view access
                    new Tuple<string, List<string>>("/file/models/" + _Action.ModelID + "/remove_sharing_from/user_id/{shareeUserId}", new List<string>() { "DELETE" })
                };

                if (!UpdateUsersSharedModelsFields(ToBeAddedUsers, _Action.ModelID, Controller_Rights_Internal.EChangeUserRightsForModelType.Add, _ErrorMessageAction)) return false;
                if (!UpdateUsersSharedModelsFields(ToBeRemovedUsers, _Action.ModelID, Controller_Rights_Internal.EChangeUserRightsForModelType.Delete, _ErrorMessageAction)) return false;
                if (!UpdateRightsForUsersUponChangeOnSharing(ToBeAddedUsers, PathsRegex, Controller_Rights_Internal.EChangeUserRightsForModelType.Add, _ErrorMessageAction)) return false;
                if (!UpdateRightsForUsersUponChangeOnSharing(ToBeRemovedUsers, PathsRegex, Controller_Rights_Internal.EChangeUserRightsForModelType.Delete, _ErrorMessageAction)) return false;

                return true;
            }

            private bool UpdateRightsForUsersUponChangeOnSharing(List<string> _RelevantIdList, Tuple<string, List<string>>[] _RightsRegex, Controller_Rights_Internal.EChangeUserRightsForModelType _Action, Action<string> _ErrorMessageAction = null)
            {
                var WaitFor = new ManualResetEvent(false);
                var InternalError = new BValue<bool>(false, EBProducerStatus.MultipleProducer);
                var DoneStack = new ConcurrentStack<bool>();
                for (var i = 0; i < _RelevantIdList.Count; i++)
                    for (var j = 0; j < _RightsRegex.Length; j++)
                        DoneStack.Push(true);

                foreach (var ChangeForUserId in _RelevantIdList)
                {
                    var CurrentUserID = ChangeForUserId;
                    foreach (var PathRegex in _RightsRegex)
                    {
                        var CurrentPathRegex = PathRegex;
                        BTaskWrapper.Run(() =>
                        {
                            if (!Controller_AtomicDBOperation.Get().GetClearanceForDBOperation(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), CurrentUserID, _ErrorMessageAction))
                            {
                                _ErrorMessageAction?.Invoke("PubSub_To_AuthService->UpdateRightsForUsersUponChangeOnSharing: Atomic operation control has failed for " + UserDBEntry.KEY_NAME_USER_ID + ": " + CurrentUserID);
                                InternalError.Set(true);
                                try { WaitFor.Set(); } catch (Exception) { }
                                return;
                            }
                            try
                            {
                                if (!Controller_Rights_Internal.Get().ChangeBaseUserRight(
                                    out bool _bInternalErrorOccured,
                                    true,/*important to set to true*/
                                    _Action,
                                    CurrentUserID,
                                    CurrentPathRegex.Item1.Replace("{shareeUserId}", ChangeForUserId, StringComparison.InvariantCulture),
                                    _ErrorMessageAction,
                                    CurrentPathRegex.Item2))
                                {
                                    if (_bInternalErrorOccured)
                                    {
                                        InternalError.Set(true);
                                        try { WaitFor.Set(); } catch (Exception) { }
                                        return;
                                    }
                                }
                            }
                            finally
                            {
                                Controller_AtomicDBOperation.Get().SetClearanceForDBOperationForOthers(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), CurrentUserID, _ErrorMessageAction);
                            }

                            DoneStack.TryPop(out bool _);
                            if (DoneStack.Count == 0)
                            {
                                try
                                {
                                    WaitFor.Set();
                                }
                                catch (Exception) { }
                            }
                        });
                    }
                }

                try
                {
                    if (_RelevantIdList.Count > 0)
                    {
                        WaitFor.WaitOne();
                    }
                    WaitFor.Close();
                }
                catch (Exception) { }

                //Retry if internal error occured
                return InternalError.Get() == false;
            }

            private bool UpdateUsersSharedModelsFields(List<string> _RelevantIdList, string _ModelID, Controller_Rights_Internal.EChangeUserRightsForModelType _Action, Action<string> _ErrorMessageAction)
            {
                foreach (var ChangeUserID in _RelevantIdList)
                {
                    if (!Controller_AtomicDBOperation.Get().GetClearanceForDBOperation(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), ChangeUserID, _ErrorMessageAction))
                    {
                        _ErrorMessageAction?.Invoke("PubSub_To_AuthService->UpdateUsersSharedModelsFields: Atomic operation control has failed for " + UserDBEntry.KEY_NAME_USER_ID + ": " + ChangeUserID);
                        return false; //Retry
                    }
                    try
                    {
                        if (!DatabaseService.GetItem(
                            UserDBEntry.DBSERVICE_USERS_TABLE(),
                            UserDBEntry.KEY_NAME_USER_ID,
                            new BPrimitiveType(ChangeUserID),
                            UserDBEntry.Properties,
                            out JObject UserObject,
                            _ErrorMessageAction))
                        {
                            _ErrorMessageAction?.Invoke("PubSub_To_AuthService->UpdateUsersSharedModelsFields: Get user database entry operation has failed. User ID: " + ChangeUserID);
                            return false; //Retry
                        }
                        else if (UserObject != null)
                        {
                            bool bUpdateDB = false;
                            var UserDeserialized = JsonConvert.DeserializeObject<UserDBEntry>(UserObject.ToString());
                            if (_Action == Controller_Rights_Internal.EChangeUserRightsForModelType.Add)
                            {
                                if (!UserDeserialized.UserSharedModels.Contains(_ModelID))
                                {
                                    UserDeserialized.UserSharedModels.Add(_ModelID);
                                    bUpdateDB = true;
                                }
                            }
                            else if (_Action == Controller_Rights_Internal.EChangeUserRightsForModelType.Delete)
                            {
                                if (UserDeserialized.UserSharedModels.Contains(_ModelID))
                                {
                                    UserDeserialized.UserSharedModels.Remove(_ModelID);
                                    bUpdateDB = true;
                                }
                            }
                            if (bUpdateDB)
                            {
                                if (!DatabaseService.UpdateItem(//Fire and forget is not suitable here since there are following calls after DB update which will change the DB structure
                                    UserDBEntry.DBSERVICE_USERS_TABLE(),
                                    UserDBEntry.KEY_NAME_USER_ID,
                                    new BPrimitiveType(ChangeUserID),
                                    JObject.Parse(JsonConvert.SerializeObject(UserDeserialized)),
                                    out JObject _, EBReturnItemBehaviour.DoNotReturn, null, _ErrorMessageAction))
                                {
                                    _ErrorMessageAction?.Invoke("PubSub_To_AuthService->UpdateUsersSharedModelsFields: Update user database entry operation has failed. User ID: " + ChangeUserID);
                                    return false; //Retry
                                }
                            }
                        }
                    }
                    finally
                    {
                        Controller_AtomicDBOperation.Get().SetClearanceForDBOperationForOthers(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), ChangeUserID, _ErrorMessageAction);
                    }
                }

                return true;
            }

            private bool UserCreatedDeletedModel(HttpListenerContext _Context, Action_ModelAction _Action, Action<string> _ErrorMessageAction = null)
            {
                if (!Controller_AtomicDBOperation.Get().GetClearanceForDBOperation(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), _Action.UserID, _ErrorMessageAction))
                {
                    _ErrorMessageAction?.Invoke("InternalCalls->PubSub_To_AuthService->UserCreatedModel: Atomic operation control has failed.");
                    return false; //Internal error, return error for retrial.
                }

                var UserID_Primitive = new BPrimitiveType(_Action.UserID);

                var PathRegexes = new Tuple<string, string[]>[]
                {
                    new Tuple<string, string[]>("/file/models/" + _Action.ModelID + "*", new string[] { "GET", "POST", "PUT", "DELETE" }),
                    new Tuple<string, string[]>("/custom_procedures/by_model/" + _Action.ModelID + "*", new string[] { "GET" })
                };
                var PathsRegexesForShared = new Tuple<string, List<string>>[]
                {
                    new Tuple<string, List<string>>("/file/models/" + _Action.ModelID + "*", new List<string>() { "GET" }), //Only view access
                    new Tuple<string, List<string>>("/custom_procedures/by_model/" + _Action.ModelID + "*", new List<string>() { "GET" }), //Only view access
                    new Tuple<string, List<string>>("/file/models/" + _Action.ModelID + "/remove_sharing_from/user_id/{shareeUserId}", new List<string>() { "DELETE" })
                };

                try
                {
                    if (_Action.ModelSharedWithUserIDs.Count > 0 && _Action.GetActionType() == Actions.EAction.ACTION_MODEL_DELETED)
                    {
                        List<string> ToBeDeletedFromShareds;
                        if (_Action.ModelSharedWithUserIDs.Contains("*"))
                        {
                            var UsersListJObject = new List<JObject>();

                            if (!DatabaseService.ScanTable(UserDBEntry.DBSERVICE_USERS_TABLE(), out UsersListJObject, _ErrorMessageAction))
                            {
                                _ErrorMessageAction?.Invoke("InternalCalls->PubSub_To_AuthService->UserCreatedDeletedModel: ScanTable has failed.");
                                return false; //Internal error, return error for retrial.
                            }

                            ToBeDeletedFromShareds = new List<string>();

                            foreach (var UserObject in UsersListJObject)
                            {
                                if (UserObject != null && UserObject.ContainsKey(UserDBEntry.KEY_NAME_USER_ID))
                                {
                                    ToBeDeletedFromShareds.Add((string)UserObject[UserDBEntry.KEY_NAME_USER_ID]);
                                }
                            }
                        }
                        else
                        {
                            ToBeDeletedFromShareds = _Action.ModelSharedWithUserIDs;
                        }

                        if (ToBeDeletedFromShareds.Count > 0)
                        {
                            if (!UpdateUsersSharedModelsFields(ToBeDeletedFromShareds, _Action.ModelID, Controller_Rights_Internal.EChangeUserRightsForModelType.Delete, _ErrorMessageAction)) return false; //Retry if internal error occured
                            if (!UpdateRightsForUsersUponChangeOnSharing(ToBeDeletedFromShareds, PathsRegexesForShared, Controller_Rights_Internal.EChangeUserRightsForModelType.Delete, _ErrorMessageAction)) return false; //Retry if internal error occuredaranceForUsers(ClearanceObtainedForUserIds, _ErrorMessageAction);
                        }
                    }
                    
                    if (!DatabaseService.GetItem(
                        UserDBEntry.DBSERVICE_USERS_TABLE(),
                        UserDBEntry.KEY_NAME_USER_ID,
                        UserID_Primitive,
                        UserDBEntry.Properties,
                        out JObject UserJObject,
                        _ErrorMessageAction))
                    {
                        _ErrorMessageAction?.Invoke("PubSub_To_AuthService->UserCreatedModel: Get user database entry operation has failed. User ID: " + _Action.UserID);
                        return false; //Internal error, return error for retrial.
                    }
                    if (UserJObject == null)
                    {
                        _ErrorMessageAction?.Invoke("PubSub_To_AuthService->UserCreatedModel: User does not found. User ID: " + _Action.UserID);
                        return true; //It should return 200 anyways.
                    }

                    bool bUpdateDB = false;
                    var UserDeserialized = JsonConvert.DeserializeObject<UserDBEntry>(UserJObject.ToString());
                    if (_Action.GetActionType() == Actions.EAction.ACTION_MODEL_CREATED)
                    {
                        if (!UserDeserialized.UserModels.Contains(_Action.ModelID))
                        {
                            UserDeserialized.UserModels.Add(_Action.ModelID);
                            bUpdateDB = true;
                        }
                    }
                    else if (_Action.GetActionType() == Actions.EAction.ACTION_MODEL_DELETED)
                    {
                        if (UserDeserialized.UserModels.Contains(_Action.ModelID))
                        {
                            UserDeserialized.UserModels.Remove(_Action.ModelID);
                            bUpdateDB = true;
                        }
                    }
                    if (bUpdateDB)
                    {
                        if (!DatabaseService.UpdateItem(//Fire and forget is not suitable here since there are following calls after DB update which will change the DB structure
                            UserDBEntry.DBSERVICE_USERS_TABLE(),
                            UserDBEntry.KEY_NAME_USER_ID,
                            UserID_Primitive,
                            JObject.Parse(JsonConvert.SerializeObject(UserDeserialized)),
                            out JObject _, EBReturnItemBehaviour.DoNotReturn, null,
                            _ErrorMessageAction))
                        {
                            return false; //Retry
                        }
                    }

                    //Double ActionType check is being done; because ChangeBaseUserRight and GrantFinalRightToAuthMethod are
                    //Http calls that also affects the UserDB table.
                    for (int i = 0; i < PathRegexes.Length; i++)
                    {
                        var Path = PathRegexes[i].Item1;
                        var Rights = PathRegexes[i].Item2.ToList();

                        if (_Action.GetActionType() == Actions.EAction.ACTION_MODEL_CREATED)
                        {
                            if (!Controller_Rights_Internal.Get().ChangeBaseUserRight(
                                out bool _bInternalErrorOccured,
                                true,/*important to set to true*/
                                Controller_Rights_Internal.EChangeUserRightsForModelType.Add,
                                _Action.UserID,
                                Path,
                                _ErrorMessageAction,
                                Rights))
                            {
                                if (_bInternalErrorOccured) return false; //Retry if internal error occured
                            }

                            if (!Controller_Rights_Internal.Get().GrantFinalRightToAuthMethod(
                                out _bInternalErrorOccured,
                                true,/*important to set to true*/
                                _Action.UserID,
                                (_Action as Action_ModelCreated).AuthMethodKey,
                                Path,
                                Rights,
                                _ErrorMessageAction))
                            {
                                if (_bInternalErrorOccured) return false; //Retry if internal error occured
                            }
                        }
                        else if (_Action.GetActionType() == Actions.EAction.ACTION_MODEL_DELETED)
                        {
                            if (!Controller_Rights_Internal.Get().ChangeBaseUserRight(
                                out bool _bInternalErrorOccured,
                                true,/*important to set to true*/
                                Controller_Rights_Internal.EChangeUserRightsForModelType.Delete,
                                _Action.UserID,
                                Path,
                                _ErrorMessageAction))
                            {
                                if (_bInternalErrorOccured) return false; //Retry if internal error occured
                            }
                        }
                    }
                }
                finally
                {
                    Controller_AtomicDBOperation.Get().SetClearanceForDBOperationForOthers(InnerProcessor, UserDBEntry.DBSERVICE_USERS_TABLE(), _Action.UserID, _ErrorMessageAction);
                }
                return true;
            }
        }
    }
}