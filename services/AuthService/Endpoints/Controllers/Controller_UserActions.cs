/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System;
using ServiceUtilities;
using Newtonsoft.Json;

namespace AuthService.Controllers
{
    public class Controller_UserActions
    {
        private static Controller_UserActions Instance = null;
        private Controller_UserActions() { }
        public static Controller_UserActions Get()
        {
            if (Instance == null)
            {
                Instance = new Controller_UserActions();
            }
            return Instance;
        }

        public bool BroadcastUserAction(Action_UserAction _Action, Action<string> _ErrorMessageAction = null)
        {
            if (_Action == null)
            {
                _ErrorMessageAction?.Invoke("Controller_UserActions->BroadcastUserAction: Action input is null.");
                return false;
            }

            return Manager_PubSubService.Get().PublishAction(
                _Action.GetActionType(), 
                JsonConvert.SerializeObject(_Action));
        }
    }
}